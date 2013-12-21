require 'uri'
require 'stringio'
require 'time'
require 'set'
require 'monitor'
require 'sup/monkey/imap'
require 'sup/monkey/set'
require 'snappy'
require 'leveldb'
require 'rmail'
require 'fileutils'

module Redwood

class GMail < Source
  include SerializeLabelsNicely

  GMAIL_HOST = "imap.gmail.com".freeze
  GMAIL_PORT = 993
  GMAIL_USE_SSL = true
  FLAG_DESCRIPTORS = %w(UID FLAGS X-GM-LABELS X-GM-MSGID)
  BODY_DESCRIPTORS = %w(RFC822.HEADER UID FLAGS X-GM-LABELS X-GM-MSGID RFC822)

  attr_accessor :username, :password
  yaml_properties :uri, :username, :password, :usual, :archived, :id, :labels

  def self.suggested_default_labels; [] end

  def initialize uri, username, password, usual=true, archived=false, id=nil, labels=[]
    raise ArgumentError, "username and password must be specified" unless username && password
    @uri = URI(uri)
    raise ArgumentError, "not a gmail URI" unless @uri.scheme == "gmail"
    super uri, true, false, id

    @username = username
    @password = password
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
    info "Start poll for Gmail source #{@username}"
    begin
      imap_login(GMAIL_HOST, @username, @password, GMAIL_PORT, GMAIL_USE_SSL)
      return unless @imap
      mailboxes = imap_mailboxes
      mailboxes.each do |mailbox|
        ids = imap_fetch_new_ids(mailbox)
        imap_fetch_new_msg(mailbox, ids, &Proc.new)
        imap_update_old_msg
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

  def imap_login(host, username, password, port = 993, ssl = true)
    debug "; connecting to gmail..."
    begin
      @imap = Net::IMAP.new host, :port => port, :ssl => ssl
      debug "; login as #{username} ..."
      @imap.login username, password
    rescue TypeError
      # 1.8 compatibility. sigh.
      @imap = Net::IMAP.new host, port, ssl
    rescue SocketError # No connectivity
      @imap = nil
    end
  end

  def imap_logout
    @imap.logout if @imap and ! @imap.disconnected?
  end

  # Returns an array of interesting mailboxes.
  #
  # Currently this method only returns the All Mail folder. We could enhance
  # this to return also the Sent, Trash and maybe also Spam folders.
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

  GMAIL_IMMUTABLE_LABELS = [:Sent, :muted, :Todo, :Inbox]

  GMAIL_TO_SUP_LABELS = {
    :Inbox => :inbox, :Sent => :sent, :Deleted => :deleted,
    :Flagged => :starred, :Draft => :draft, :Spam => :spam, :Important => :important
  }

  SUP_TO_GMAIL_LABELS = GMAIL_TO_SUP_LABELS.invert

  def gmail_label_to_sup_label(label)
    if GMAIL_TO_SUP_LABELS.has_key?(label)
      GMAIL_TO_SUP_LABELS[label]
    else
      Net::IMAP.decode_utf7(label.to_s).downcase.to_sym
    end
  end

  def sup_label_to_gmail_label(label)
    if GMAIL_IMMUTABLE_LABELS.member?(label)
      nil
    elsif SUP_TO_GMAIL_LABELS.has_key?(label)
      SUP_TO_GMAIL_LABELS[label]
    else
      Net::IMAP.encode_utf7(label.to_s).downcase
    end
  end

  def convert_gmail_labels(labels)
    labels = (labels || []).map do |l|
      gmail_label_to_sup_label(l)
    end
    Set.new(labels)
  end

  def convert_sup_labels(labels)
    labels.map do |l|
      sup_label_to_gmail_label(l)
    end.compact
  end

  # Fetch new messages from the Gmail account and add them to the local repo
  # (leveldb) and the Xapian index.
  def imap_fetch_new_ids(mailbox)
    info "; fetch new messages from #{mailbox}"
    @imap.examine folder

    uidvalidity = @imap.responses["UIDVALIDITY"].first
    uidnext = @imap.responses["UIDNEXT"].first
    uidvaliditylast = get_mailbox_uidvalidity(mailbox)
    uidlast = get_mailbox_uidlast(mailbox).to_i

    ids = []

    #debug "; uidvalidity old: #{uidvaliditylast} (#{uidvaliditylast.class}) - new: #{uidvalidity} (#{uidvalidity.class})"

    if uidvalidity == uidvaliditylast
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

  # This methods loads the labels of all messages in the Gmail account (in
  # batches of 20 messages) and compares them with the local labels updating
  # when differences are detected.
  def imap_update_old_msg
    info "; update flags on remote server"
    @imap.select folder
    ids = @imap.fetch(1..-1, "UID").map { |msg| msg.attr["UID"] } || []
    debug "Update messages #{ids.first} #{ids.last}"
    index = Redwood::Index.instance
    raise FatalSourceError if index.nil?
    while ! (range = ids.shift 20).empty?
      query = range.first .. range.last
      #debug "; fetching flags #{query.inspect} from gmail server"

      data = []
      Timeout.timeout(120) do
        data = @imap.uid_fetch(query, FLAG_DESCRIPTORS) || []
      end

      data.each do |msg|
        uid = msg.attr["X-GM-MSGID"] || msg.attr["UID"]
        info "; get message #{id} #{uid}"
        old_msg = load_old_message(uid)
        if old_msg.nil?
          warn "; message #{uid} missing from index"
          next
        end

        # The following code follows the offlineimap sync algorithm to sync the
        # labels. In our implementation the local repository is the Xapian
        # index, the remote repository is the remote Gmail and the status is
        # stored in the leveldb database.
        remote_labels = convert_gmail_labels(msg.attr["X-GM-LABELS"])
        local_labels = old_msg.labels - [:attachment, :unread]
        index_labels = raw_labels(uid)
        #debug "; remote: #{remote_labels} #{remote_labels.class} local: #{local_labels} #{local_labels.class} state: #{index_labels} #{index_labels.class}"

        # Sync labels Remote -> Local
        # Get differences bettwen remote and index labels
        added_remote_labels = remote_labels - index_labels
        removed_remote_labels = index_labels - remote_labels

        #debug "; added_remote #{added_remote_labels}  removed_remote: #{removed_remote_labels}"

        local_labels = local_labels + added_remote_labels - removed_remote_labels
        index_labels = index_labels + added_remote_labels - removed_remote_labels

        # Sync labels Local -> Remote
        # Get differences between index and local repo
        added_local_labels = local_labels - index_labels
        removed_local_labels = index_labels - local_labels

        #debug "; added_local #{added_local_labels}  removed_local: #{removed_local_labels}"

        remote_labels = remote_labels + added_local_labels - removed_local_labels
        index_labels = index_labels + added_local_labels - removed_local_labels

        # Save the resulting labels
        if ! added_remote_labels.empty? or ! removed_remote_labels.empty? or
          ! added_local_labels.empty? or ! removed_local_labels.empty?
          #debug "; resulting remote: #{remote_labels} local: #{local_labels} state: #{index_labels}"
          old_msg.labels = local_labels
          index.update_message_state old_msg
          @imap.store(msg.seqno, "X-GM-LABELS", convert_sup_labels(remote_labels)).inspect
          leveldb_put "#{uid}/labels", index_labels
        else
          #debug "; no label changes detected"
        end
      end
    end
    info "; finished updating flags on remote server"
  end

  def imap_fetch_new_msg(mailbox, ids, &block)
    while ! (range = ids.shift 20).empty?
      query = range.first .. range.last
      debug "; fetching messages #{query.inspect} from gmail server"

      data = []
      Timeout.timeout(120) do
        data = @imap.uid_fetch(query, BODY_DESCRIPTORS) || []
      end

      data.each_with_index do |msg,i|
        labels = convert_gmail_labels(msg.attr["X-GM-LABELS"])
        body = msg.attr["RFC822"]
        header = msg.attr["RFC822.HEADER"]
        uid = msg.attr["X-GM-MSGID"] || msg.attr["UID"]
        leveldb_put "#{uid}/body", body
        leveldb_put "#{uid}/header", header
        leveldb_put "#{uid}/labels", labels
        debug "; add message #{uid} LABELS: #{labels} "
        Proc.new.call :add,
          :info => uid.to_i,
          :labels => labels,
          :progress => i.to_f/data.size
        set_mailbox_uidlast(mailbox, msg.attr["UID"])
      end
    end
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
    leveldb_get("#{id}/header").gsub(/\r\n/, "\n")
  end

  def raw_message id
    leveldb_get("#{id}/body").gsub(/\r\n/, "\n")
  end

  def raw_labels id
    leveldb_get("#{id}/labels")
  end

  private

  # Loads message from index.
  #
  # This method first builds the message from the source using the UID of the
  # email. Unfortunately the message that comes from the source has no labels so
  # we need to load the message again from the Index using the message id
  # instead.
  def load_old_message(uid)
    msg = Message.build_from_source(self, uid)
    return Index.build_message(msg.id)
  end

  def leveldb_put(key, val)
    @mutex.synchronize do
      @db.put key, YAML::dump(val)
    end
  end

  def leveldb_get(key)
    val = nil
    @mutex.synchronize do
      val = @db.get(key)
    end
    return val.nil? ? nil : YAML::load(val)
  end
end

end
