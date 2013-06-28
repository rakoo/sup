require 'uri'
require 'stringio'
require 'time'
require 'set'
require 'monitor'
require 'sup/monkey/imap'
require 'leveldb'
require 'rmail'
require 'fileutils'

module Redwood

class GMail < Source
  include SerializeLabelsNicely

  FLAG_DESCRIPTORS = %w(UID FLAGS X-GM-LABELS X-GM-MSGID)
  BODY_DESCRIPTORS = %w(RFC822.HEADER UID FLAGS X-GM-LABELS X-GM-MSGID RFC822)

  attr_accessor :username, :password
  yaml_properties :uri, :username, :password, :usual, :archived, :id, :labels

  def initialize uri, username, password, usual=true, archived=false, id=nil, labels=[]
    raise ArgumentError, "username and password must be specified" unless username && password
    @uri = URI(uri)
    raise ArgumentError, "not a gmail URI" unless @uri.scheme == "gmail"
    super uri, true, false, id

    @username = username
    @password = password
    @port = 993
    @ssl = true
    @mutex = Mutex.new
    @imap = nil
    @ids = []
    @data = []
    @labels = Set.new((labels || []) - LabelManager::RESERVED_LABELS)
    @mutex = Monitor.new
    @path = File.join(Redwood::BASE_DIR, "gmail", @username)
    FileUtils.mkdir_p(@path)
    @db = LevelDB::DB.new @path
  end

  def imap_login(host, username, password, port = 993, ssl = true)
    debug "; connecting to gmail..."
    begin
      @imap = Net::IMAP.new host, :port => port, :ssl => ssl
    rescue TypeError
      # 1.8 compatibility. sigh.
      @imap = Net::IMAP.new host, port, ssl
    end
    debug "; login as #{username} ..."
    @imap.login username, password
  end

  def imap_logout
    @imap.logout if @imap and ! @imap.disconnected?
  end

  # Returns an array of interesting mailboxes.
  def imap_mailboxes
    mailboxes = @imap.list "", "*"
    mailboxes.select { |m| m.attr.include?(:All) }.map { |m| m.name }
  end

  def get_mailbox_uidlast(mailbox)
    leveldb_get("#{mailbox}/uidlast")
  end

  def set_mailbox_uidlast(mailbox, uidlast)
    leveldb_put("#{mailbox}/uidlast", uidlast)
  end

  def get_mailbox_uidvalidity(mailbox)
    leveldb_get("#{mailbox}/uidvalidity")
  end

  def set_mailbox_uidvalidity(mailbox, uidvalidity)
    leveldb_put("#{mailbox}/uidvalidity", uidvalidity)
  end

  def gmail_label_to_sup_label(label)
    case label
      when "Inbox"
        :inbox
      when "Sent"
        :sent
      when "Deleted"
        :deleted
      when "Flagged"
        :starred
      when "Draft"
        :draft
      when "Spam"
        :spam
      else
        Net::IMAP.decode_utf7(label.to_s).to_sym
    end
  end

  def imap_fetch_new_ids(mailbox)
    info "; fetch new messages from #{mailbox}"
    @imap.examine folder

    uidvalidity = @imap.responses["UIDVALIDITY"].first
    uidnext = @imap.responses["UIDNEXT"].first
    uidvaliditylast = get_mailbox_uidvalidity(mailbox)
    uidlast = get_mailbox_uidlast(mailbox).to_i

    ids = []

    if uidvalidity.to_s == uidvaliditylast
      ids = ((uidlast + 1) .. (uidnext -1)).to_a
      debug "; downloading new messages... (Total: #{ids.size}) [#{ids.first} .. #{ids.last}]"
    elsif uidvaliditylast.nil?
      ids = @imap.uid_search(["NOT", "DELETED"]) || []
      set_mailbox_uidvalidity mailbox, uidvalidity
      debug "; first time, downloading all messages... (Total: #{ids.size}) [#{ids.first} .. #{ids.last}]"
    else
      ids = @imap.uid_search(["NOT", "DELETED"]) || []
      set_mailbox_uidvalidity mailbox, uidvalidity
      debug "; uidvalidity mistmatch, downloading all messages again as punishment (Total: #{ids.size}) [#{ids.first} .. #{ids.last}]"
    end
    ids
  end

  def poll
    info "Start poll for Gmail source #{@username}"
    begin
      imap_login("imap.gmail.com", @username, @password, @port, @ssl)
      mailboxes = imap_mailboxes
      mailboxes.each do |mailbox|
        ids = imap_fetch_new_ids(mailbox)
        while ! (range = ids.shift 20).empty?
          query = range.first .. range.last
          debug "; fetching messages #{query.inspect} from gmail server"

          data = []
          Timeout.timeout(120) do
            data = @imap.uid_fetch(query, BODY_DESCRIPTORS) || []
          end

          data.each_with_index do |msg,i|
            labels = (msg.attr["X-GM-LABELS"] || []).map do |l|
              gmail_label_to_sup_label(l)
            end
            flags = (msg.attr["FLAGS"] || []).map { |f| f.to_s.downcase.to_sym }
            labels += [:unread] unless flags.include?(:seen)
            body = msg.attr["RFC822"]
            header = msg.attr["RFC822.HEADER"]
            uid = msg.attr["X-GM-MSGID"] || msg.attr["UID"]
            @db.put "#{uid}/body", body
            @db.put "#{uid}/header", header
            debug "; add message #{uid} LABELS: #{labels}  FLAGS: #{flags} "
            yield :add,
              :info => uid.to_i,
              :labels => Set.new(labels).merge(labels),
              :progress => i.to_f/@data.size
            set_mailbox_uidlast(mailbox, msg.attr["UID"])
          end
        end
      end
    ensure
      imap_logout
    end
  end

  def go_idle
    @mutex.synchronize do
      @running = false
    end
  end

  def load_header id
    parse_raw_email_header StringIO.new(raw_header(id))
  end

  def load_message id
    RMail::Parser.read raw_message(id)
  end

  def each_raw_message_line id
    StringIO.new(raw_message(id)).each { |l| yield l }
  end

  # TODO: Store this somewhere and execute the actual append to GMail using
  # UIDPLUS during the polling.
  def store_message date, from_email, &block
    message = StringIO.new
    yield message
    message.string.gsub! /\n/, "\r\n"
    safely { @imap.append mailbox, message.string, [:Seen], Time.now }
  end

  # Returns the all folder name.
  def folder
    return @folder if @folder

    # TODO: Investigate a way to ask the IMAP server to return only the mailbox
    # with the \All property on it. Getting all mailboxes and then searching for
    # that one property can be heavy for accounts with huge number of mailboxes.
    mailboxes = @imap.list "", "*"

    mailbox = mailboxes.select { |m| m.attr.include?(:All) }.first
    raise FatalSourceError if mailbox.nil?
    @folder = mailbox.name
  end

  def raw_header id
    @mutex.synchronize do
      @db.get("#{id}/header").gsub(/\r\n/, "\n")
    end
  end

  def raw_message id
    @mutex.synchronize do
      @db.get("#{id}/body").gsub(/\r\n/, "\n")
    end
  end

  private

  def leveldb_put(key, val)
    @mutex.synchronize do
      @db.put "key", YAML::dump(val)
    end
  end

  def leveldb_get(key)
    val = @db.get(key)
    return nil if val.nil?
    return YAML::load(val)
  end
end

end
