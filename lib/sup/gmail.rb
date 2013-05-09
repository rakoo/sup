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

  attr_accessor :username, :password
  yaml_properties :uri, :username, :password, :usual, :archived, :id, :labels

  def initialize uri, username, password, usual=true, archived=false, id=nil, labels=[]
    raise ArgumentError, "username and password must be specified" unless username && password
    @uri = URI(uri)
    raise ArgumentError, "not a gmail URI" unless @uri.scheme == "gmail"
    super uri, true, false, id

    @username = username
    @password = password
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

  def poll
    @running = true
      info "Polling new messages for Gmail #{@username}"

      imap_fields = %w(RFC822.HEADER UID FLAGS X-GM-LABELS X-GM-MSGID RFC822)

      begin
        debug "; connection to gmail..."
        begin
          @imap = Net::IMAP.new "imap.gmail.com", :port => 993, :ssl => true
        rescue TypeError
          # 1.8 compatibility. sigh.
          @imap = Net::IMAP.new "imap.gmail.com", 993, true
        end

        debug "; login as #{@username} ..."
        @imap.login @username, @password

        @imap.examine folder

        debug "; open successfully"

        @uidvalidity = @imap.responses["UIDVALIDITY"].first
        @uidnext = @imap.responses["UIDNEXT"].first

        debug "; server uidnext #{@uidnext} uidvalidity #{@uidvalidity}"

        if self.uidvaliditylast.nil?
          debug "; first time, downloading all messages"
          @ids = @imap.uid_search(["NOT", "DELETED"]) || []
          self.uidvaliditylast = @uidvalidity
        else
          debug "; check uidvalidity #{@uidvalidity} #{self.uidvaliditylast}"
          raise OutOfSyncSourceError unless @uidvalidity.to_s == self.uidvaliditylast.to_s
          debug "; check only for new messages"
          @ids = ((self.uidlast + 1) .. (@uidnext -1)).to_a
        end
        debug "; got #{@ids.size} new messages [#{@ids.first} .. #{@ids.last}]"

        while ! (ids = @ids.shift 20).empty?
          @query = ids.first .. ids.last
          debug "; requesting messages #{@query.inspect} from gmail server"

          Timeout.timeout(120) do
            @data = @imap.uid_fetch(@query, imap_fields) || []
          end

          @data.each_with_index do |msg,i|
            labels = (msg.attr["X-GM-LABELS"] || []).map do |l|
              case l
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
                Net::IMAP.decode_utf7(l.to_s).to_sym
              end
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
            self.uidlast = msg.attr["UID"]
          end
          break if ! @running
        end
      rescue => e
        raise FatalSourceError, "While communicating with GMail server (type #{e.class.name}): #{e.message.inspect}"
      ensure
        @imap.close if @imap
      end
      nil
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

  def uidvaliditylast
    @db.get("uidvaliditylast")
  end

  def uidvaliditylast=(val)
    @db.put "uidvaliditylast", val.to_s
  end

  def uidlast
    @db.get("uidlast").to_i
  end

  def uidlast=(val)
    @db.put "uidlast", val.to_s
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
end

end
