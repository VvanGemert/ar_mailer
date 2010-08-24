require 'optparse'
require 'net/smtp'
require 'net/imap'
require 'smtp_tls' unless Net::SMTP.instance_methods.include?("enable_starttls_auto")

##
# Hack in RSET

module Net # :nodoc:
class SMTP # :nodoc:

  unless instance_methods.include? 'reset' then
    ##
    # Resets the SMTP connection.

    def reset
      getok 'RSET'
    end
  end

end
end

##
# ActionMailer::ARSendmail delivers email from the email table to the
# SMTP server configured in your application's config/environment.rb.
# ar_sendmail does not work with sendmail delivery.
#
# ar_mailer can deliver to SMTP with TLS using smtp_tls.rb borrowed from Kyle
# Maxwell's action_mailer_optional_tls plugin.  Simply set the :tls option in
# ActionMailer::Base's smtp_settings to true to enable TLS.
#
# See ar_sendmail -h for the full list of supported options.
#
# The interesting options are:
# * --daemon
# * --mailq

module ActionMailer; end

class ActionMailer::ARSendmail

  ##
  # The version of ActionMailer::ARSendmail you are running.

  VERSION = '2.1.8'

  ##
  # Maximum number of times authentication will be consecutively retried

  MAX_AUTH_FAILURES = 2

  ##
  # Email delivery attempts per run

  attr_accessor :batch_size

  ##
  # Seconds to delay between runs

  attr_accessor :delay

  ##
  # Maximum age of emails in seconds before they are removed from the queue.

  attr_accessor :max_age

  ##
  # Be verbose

  attr_accessor :verbose


  ##
  # True if only one delivery attempt will be made per call to run

  attr_reader :once

  ##
  # Times authentication has failed

  attr_accessor :failed_auth_count

  @@pid_file = nil

  def self.remove_pid_file
    if @@pid_file
      require 'shell'
      sh = Shell.new
      sh.rm @@pid_file
    end
  end

  ##
  # Prints a list of unsent emails and the last delivery attempt, if any.
  #
  # If ActiveRecord::Timestamp is not being used the arrival time will not be
  # known.  See http://api.rubyonrails.org/classes/ActiveRecord/Timestamp.html
  # to learn how to enable ActiveRecord::Timestamp.

  def self.mailq
	emails = ActionMailer::Base.email_class.all(:order => :priority)
	
    if emails.empty? then
      puts "Mail queue is empty"
      return
    end

    total_size = 0

    puts "-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------"
    emails.each do |email|
      size = email.mail.length
      total_size += size

      create_timestamp = email.created_at rescue
                         Time.at(email.created_date) rescue # for Robot Co-op
                         nil

      created = if create_timestamp.nil? then
                  '             Unknown'
                else
                  create_timestamp.strftime '%a %b %d %H:%M:%S'
                end

      puts "%10d %8d %s  %s" % [email.id, size, created, email.from]
      if email.last_send_attempt > 0 then
        puts "Last send attempt: #{Time.at email.last_send_attempt}"
      end
      puts "                                         #{email.to}"
      puts
    end

    puts "-- #{total_size/1024} Kbytes in #{emails.length} Requests."
  end

  ##
  # Processes command line options in +args+

  def self.process_args(args)
    name = File.basename $0

    options = {}
    options[:Chdir] = '.'
    options[:Daemon] = false
    options[:Delay] = 60
    options[:MaxAge] = 86400 * 7
    options[:Once] = false
    options[:RailsEnv] = ENV['RAILS_ENV']
    options[:Port] = 993
    options[:Login] = ''
    options[:Imap] = ''
    options[:Password] = ''
    options[:DryRun] = false
    options[:Pidfile] = options[:Chdir] + '/log/ar_sendmail.pid'

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{name} [options]"
      opts.separator ''

      opts.separator "#{name} scans the email table for new messages and sends them to the"
      opts.separator "website's configured SMTP host."
      opts.separator ''
      opts.separator "#{name} must be run from a Rails application's root."

      opts.separator ''
      opts.separator 'Sendmail options:'

      opts.on("-b", "--batch-size BATCH_SIZE",
              "Maximum number of emails to send per delay",
              "Default: Deliver all available emails", Integer) do |batch_size|
        options[:BatchSize] = batch_size
      end

      opts.on(      "--delay DELAY",
              "Delay between checks for new mail",
              "in the database",
              "Default: #{options[:Delay]}", Integer) do |delay|
        options[:Delay] = delay
      end

      opts.on(      "--max-age MAX_AGE",
              "Maxmimum age for an email. After this",
              "it will be removed from the queue.",
              "Set to 0 to disable queue cleanup.",
              "Default: #{options[:MaxAge]} seconds", Integer) do |max_age|
        options[:MaxAge] = max_age
      end

      opts.on("-o", "--once",
              "Only check for new mail and deliver once",
              "Default: #{options[:Once]}") do |once|
        options[:Once] = once
      end

      opts.on("-d", "--daemonize",
              "Run as a daemon process",
              "Default: #{options[:Daemon]}") do |daemon|
        options[:Daemon] = true
      end

      opts.on("-p", "--pidfile PIDFILE",
              "Set the pidfile location",
              "Default: #{options[:Chdir]}#{options[:Pidfile]}", String) do |pidfile|
        options[:Pidfile] = pidfile
      end

      opts.on(      "--mailq",
              "Display a list of emails waiting to be sent") do |mailq|
        options[:MailQ] = true
      end

      opts.separator ''
      opts.separator 'Setup Options:'

      opts.separator ''
      opts.separator 'Generic Options:'

      opts.on("-c", "--chdir PATH",
              "Use PATH for the application path",
              "Default: #{options[:Chdir]}") do |path|
        usage opts, "#{path} is not a directory" unless File.directory? path
        usage opts, "#{path} is not readable" unless File.readable? path
        options[:Chdir] = path
      end

      opts.on("-e", "--environment RAILS_ENV",
              "Set the RAILS_ENV constant",
              "Default: #{options[:RailsEnv]}") do |env|
        options[:RailsEnv] = env
      end

      opts.on("-v", "--[no-]verbose",
              "Be verbose",
              "Default: #{options[:Verbose]}") do |verbose|
        options[:Verbose] = verbose
      end
			
			opts.on("-i", "--imap IMAP",
              "Imap server used to check for bounces",
              "Default: false", String) do |imap|
        options[:Imap] = imap
      end
      
      opts.on("-l", "--login LOGIN",
              "login name to check for bounces",
              "Default: false", String) do |login|
        options[:Login] = login
      end
      
      opts.on( "--password PASSWORD",
              "password name to check for bounces",
              "Default: false", String) do |password|
        options[:Password] = password
      end
      
      opts.on( "--port PORT",
              "port to check for bounces",
              "Default: #{options[:Port]}", Integer) do |port|
        options[:Port] = port
      end
      
      opts.on( "-k", "--bouncecheck",
              "check for bounces",
              "Default: false") do |bounce_check|
        options[:Bouncecheck] = true
      end
      
      opts.on("-f", "--dry-run",
							"Dry run: don't send any emails",
              "Default: Deliver all available emails\n", options[:DryRun]) do |dry_run|
        options[:DryRun] = dry_run
      end
      
      opts.on("-h", "--help",
              "You're looking at it") do
        usage opts
      end

      opts.on("--version", "Version of ARMailer") do
        usage "ar_mailer #{VERSION} (adzap fork)"
      end

      opts.separator ''
    end

    opts.parse! args

    ENV['RAILS_ENV'] = options[:RailsEnv]

    Dir.chdir options[:Chdir] do
      begin
        require 'config/environment'
        require 'action_mailer/ar_mailer'
      rescue LoadError
        usage opts, <<-EOF
#{name} must be run from a Rails application's root to deliver email.
#{Dir.pwd} does not appear to be a Rails application root.
        EOF
      end
    end

    return options
  end

  ##
  # Processes +args+ and runs as appropriate

  def self.run(args = ARGV)
    options = process_args args

    if options.include? :MailQ then
      mailq
      exit
    end

    if options[:Daemon] then
      require 'webrick/server'
      @@pid_file = File.expand_path(options[:Pidfile], options[:Chdir])
      if File.exists? @@pid_file
        # check to see if process is actually running
        pid = ''
        File.open(@@pid_file, 'r') {|f| pid = f.read.chomp }
        if system("ps -p #{pid} | grep #{pid}") # returns true if process is running, o.w. false
          $stderr.puts "Warning: The pid file #{@@pid_file} exists and ar_sendmail is running. Shutting down."
          exit -1
        else
          # not running, so remove existing pid file and continue
          self.remove_pid_file
          $stderr.puts "ar_sendmail is not running. Removing existing pid file and starting up..."
        end
      end
      WEBrick::Daemon.start
      File.open(@@pid_file, 'w') {|f| f.write("#{Process.pid}\n")}
    end

    new(options).run

  rescue SystemExit
    raise
  rescue SignalException
    exit
  rescue Exception => e
    $stderr.puts "Unhandled exception #{e.message}(#{e.class}):"
    $stderr.puts "\t#{e.backtrace.join "\n\t"}"
    exit -2
  end

  ##
  # Prints a usage message to $stderr using +opts+ and exits

  def self.usage(opts, message = nil)
    if message then
      $stderr.puts message
      $stderr.puts
    end

    $stderr.puts opts
    exit 1
  end

  ##
  # Creates a new ARSendmail.
  #
  # Valid options are:
  # <tt>:BatchSize</tt>:: Maximum number of emails to send per delay
  # <tt>:Delay</tt>:: Delay between deliver attempts
  # <tt>:Once</tt>:: Only attempt to deliver emails once when run is called
  # <tt>:Verbose</tt>:: Be verbose.

  def initialize(options = {})
    options[:Delay] ||= 60
    options[:MaxAge] ||= 86400 * 7

    @batch_size = options[:BatchSize]
    @delay = options[:Delay]
    @once = options[:Once]
    @verbose = options[:Verbose]
    @max_age = options[:MaxAge]
		@dry_run = options[:DryRun]
		@imap = { :host => options[:Imap], :port => options[:Port], :user => options[:Login], :password => options[:Password] }
		@bouncecheck = options[:Bouncecheck]
    @failed_auth_count = 0
  end

  ##
  # Removes emails that have lived in the queue for too long.  If max_age is
  # set to 0, no emails will be removed.

  def cleanup
    return if @max_age == 0
    timeout = Time.now - @max_age
    conditions = ['last_send_attempt > 0 and created_at < ?', timeout]
    mail = ActionMailer::Base.email_class.destroy_all conditions

    log "expired #{mail.length} emails from the queue"
  end

  ##
  # Delivers +emails+ to ActionMailer's SMTP server and destroys them.

  def deliver(emails)
    settings = [
      smtp_settings[:domain],
      (smtp_settings[:user] || smtp_settings[:user_name]),
      smtp_settings[:password],
      smtp_settings[:authentication]
    ]

    smtp = Net::SMTP.new(smtp_settings[:address], smtp_settings[:port])
    if smtp.respond_to?(:enable_starttls_auto)
      smtp.enable_starttls_auto unless smtp_settings[:tls] == false
    else
      settings << smtp_settings[:tls]
    end

    smtp.start(*settings) do |session|
      @failed_auth_count = 0
      until emails.empty? do
        email = emails.shift
        begin
        	if @dry_run
              res = 'DRY RUN'
          else
          	res = session.send_message email.mail, email.from, email.to
          	email.destroy
          end
          log "sent email %011d from %s to %s: %p" %
                [email.id, email.from, email.to, res]
        rescue Net::SMTPFatalError => e
          log "5xx error sending email %d, removing from queue: %p(%s):\n\t%s" %
                [email.id, e.message, e.class, e.backtrace.join("\n\t")]
          email.failed = Time.now.to_i
          email.save rescue nil unless @dry_run
          session.reset
        rescue Net::SMTPServerBusy => e
        	email.failed = Time.now.to_i
          email.save rescue nil unless @dry_run
          log "server too busy, stopping delivery cycle"
          session.reset
        rescue Net::SMTPUnknownError, Net::SMTPSyntaxError, TimeoutError, Timeout::Error => e
          email.failed = Time.now.to_i
          email.save rescue nil unless @dry_run
          log "error sending email %d: %p(%s):\n\t%s" %
                [email.id, e.message, e.class, e.backtrace.join("\n\t")]
          session.reset
        end
      end
    end
  rescue Net::SMTPAuthenticationError => e
    @failed_auth_count += 1
    if @failed_auth_count >= MAX_AUTH_FAILURES then
      log "authentication error, giving up: #{e.message}"
      raise e
    else
      log "authentication error, retrying: #{e.message}"
    end
    sleep delay
  rescue Net::SMTPServerBusy, SystemCallError, OpenSSL::SSL::SSLError
    # ignore SMTPServerBusy/EPIPE/ECONNRESET from Net::SMTP.start's ensure
  end

  def deliver_newsletter(newsletter, users)
  
      settings = [
        smtp_settings[:domain],
        (smtp_settings[:user] || smtp_settings[:user_name]),
        smtp_settings[:password],
        smtp_settings[:authentication]
      ]

      smtp = Net::SMTP.new(smtp_settings[:address], smtp_settings[:port])
      if smtp.respond_to?(:enable_starttls_auto)
        smtp.enable_starttls_auto unless smtp_settings[:tls] == false
      else
        settings << smtp_settings[:tls]
      end

      smtp.start(*settings) do |session|
  	    @failed_auth_count = 0
      	until users.empty? do
      	  user = users.shift
      	  begin
      	  	if @dry_run
              res = 'DRY RUN'
           else
            res = session.send_message newsletter.mail, newsletter.from, user.email
           end
            log "sent email %011d from %s to %s: %p" %
                [newsletter.id, newsletter.from, user.email, res]
          rescue Net::SMTPFatalError => e
            log "5xx error sending email %d, removing from queue: %p(%s):\n\t%s" %
                [email.id, e.message, e.class, e.backtrace.join("\n\t")]
            session.reset
          rescue Net::SMTPServerBusy => e
            log "server too busy, stopping delivery cycle"
          return
          rescue Net::SMTPUnknownError, Net::SMTPSyntaxError, TimeoutError, Timeout::Error => e
            log "error sending email %d: %p(%s):\n\t%s" %
                [email.id, e.message, e.class, e.backtrace.join("\n\t")]
            session.reset
          end
        end
  	  end
  	  rescue Net::SMTPAuthenticationError => e
        @failed_auth_count += 1
        if @failed_auth_count >= MAX_AUTH_FAILURES then
      	  log "authentication error, giving up: #{e.message}"
      	  raise e
       else
          log "authentication error, retrying: #{e.message}"
        end
        sleep delay
  	  rescue Net::SMTPServerBusy, SystemCallError, OpenSSL::SSL::SSLError
      # ignore SMTPServerBusy/EPIPE/ECONNRESET from Net::SMTP.start's ensure
  end

  ##
  # Prepares ar_sendmail for exiting

  def do_exit
    log "caught signal, shutting down"
    self.class.remove_pid_file
    exit 130
  end

  ##
  # Returns emails in email_class that haven't had a delivery attempt in the
  # last 300 seconds.

  def find_emails
    options = { :conditions => ['last_send_attempt < ? AND failed IS NULL', Time.now.to_i - 300], :order => :priority }
    options[:limit] = batch_size unless batch_size.nil?
    mail = ActionMailer::Base.email_class.find :all, options

    log "found #{mail.length} emails to send"
    mail
  end
  
  def find_newsletter
  
  	options = { :conditions => ['cancelled != 1 AND completed != 1'] }
    newsletter = ActionMailer::Base.newsletter_class.find :first, options

    log "found newsletter with title: #{newsletter.title}" unless newsletter.nil?
    log "no newsletters found" unless !newsletter.nil?
    newsletter
  
  end
   	
  def find_users(limit, offset)
  	
  	options = { :conditions => ['newsletter = 1 AND email IS NOT NULL'], :limit => limit, :offset => offset, :order => "id" }
  	users = ActionMailer::Base.user_class.find :all, options
  
  	if !users.nil? && users.length < limit
      
  	end
  	log "found #{users.length} users to send a newsletter"
    users
    
  end 	
   	
  ##
  # Installs signal handlers to gracefully exit.

  def install_signal_handlers
    trap 'TERM' do do_exit end
    trap 'INT'  do do_exit end
  end

  ##
  # Logs +message+ if verbose

  def log(message)
    $stderr.puts message if @verbose
    ActionMailer::Base.logger.info "ar_sendmail: #{message}"
  end

  ##
  # Scans for emails and delivers them every delay seconds.  Only returns if
  # once is true.

  def run
    install_signal_handlers

    loop do
      begin
        cleanup
        
        emails = find_emails
        already_send = emails.empty? ? 0 : emails.length
        deliver(emails) unless emails.empty?
        
        newsletter = find_newsletter
        
        unless newsletter.nil? || batch_size.nil?
 	      	offset = newsletter.mails_send.nil? ? 0 : newsletter.mails_send
 		  		limit = batch_size - already_send
 					 
          users = find_users(limit, offset)
        
          update = {}
          update[:mails_send] = offset + users.length unless users.empty?
        	
          if (!users.empty? && users.length < limit) || users.empty?
            update[:completed] = 1
          end
          
          # Deliver newsletter
          newsletter.update_attributes(update) unless @dry_run
          deliver_newsletter(newsletter, users) unless users.empty?
          
        end
        
        # Check for bounces
        check_bounces unless @dry_run
        
      rescue ActiveRecord::Transactions::TransactionError
      end
      break if @once
      sleep @delay
    end
  end

  ##
  # Proxy to ActionMailer::Base::smtp_settings.  See
  # http://api.rubyonrails.org/classes/ActionMailer/Base.html
  # for instructions on how to configure ActionMailer's SMTP server.
  #
  # Falls back to ::server_settings if ::smtp_settings doesn't exist for
  # backwards compatibility.

  def smtp_settings
    ActionMailer::Base.smtp_settings rescue ActionMailer::Base.server_settings
  end

	def check_bounces

		if @bouncecheck
	    begin
	      imap = Net::IMAP.new(@imap[:host], @imap[:port], true)
	      imap.login(@imap[:user], @imap[:password])
	      imap.select('INBOX')
	    
	      imap.uid_search(["NOT", "DELETED"]).each do |message_id|
	        msg = imap.uid_fetch(message_id,'RFC822')[0].attr['RFC822']
	        email = TMail::Mail.parse(msg)
	        receive(email)
	        #Mark message as deleted and it will be removed from storage when user session closed
	        imap.uid_store(message_id, "+FLAGS", [:Deleted])
	      end
	      # tell server to permanently remove all messages flagged as :Deleted
	      imap.expunge
	      imap.logout
	      imap.disconnect
	    rescue Net::IMAP::NoResponseError => e
	      log e
	    rescue Net::IMAP::ByeResponseError => e
	      log e
	    rescue => e
	      log e
	    end
		end
		
  end

  def receive(email)
     bounce = BouncedDelivery.from_email(email)
     if(bounce.status_info > 3)
        log "User bounced with email: #{bounce.sender}"
        user = ActionMailer::Base.user_class.find_by_email(bounce.sender)
  
  			if !user.nil?
      		user.update_attribute(:bounced_at, Time.now)
  			end
     end
  end

end

##
# Checking for bounced delivery
# 

class BouncedDelivery

  attr_accessor :status_info, :sender, :subject

  def self.from_email(email)
    returning(bounce = self.new) do
      
      if(email.subject.match(/Mail delivery failed/i))
        bounce.status_info = 6
      elsif(email.subject.match(/Delivery Status Notification/i))
        bounce.status_info = 8
      elsif(email.header.to_s.match(/X-Failed-Recipient/i))
        bounce.status_info = 10
      else
        bounce.status_info = 2
      end
      
      if bounce.status_info > 3
        bounce.subject = email.subject
        bounce.sender = bounce.check_recipient(email.header)
      end
    end
  end

  def check_recipient(header)
      header['x-failed-recipients'].body.to_s unless header['x-failed-recipients'].nil?
  end

  def status
    case status_info
    when 10
      'Failed - X-Failed-Recipient'
    when 8
      'Failed - Delivery Status Notification'
    when 6
      'Failed - Mail delivery failed'
    when 2
      'Success'
    end
  end
end