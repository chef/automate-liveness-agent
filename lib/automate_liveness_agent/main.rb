require "automate_liveness_agent/config"
require "automate_liveness_agent/liveness_update_sender"

module AutomateLivenessAgent

  class Pipeline

    def initialize(implementation)
      @implementation = implementation
      @exit_code = 0
      @message = ""
    end

    def run(method_name)
      if @exit_code == 0
        @exit_code, @message = @implementation.public_send(method_name)
      end
      self
    end

    def finish
      if @exit_code != 0
        $stderr.print("#{@message}\n")
      end

      Kernel.exit(@exit_code)
    end

  end

  class Main

    USAGE = "Usage: automate-liveness-agent [config_file]".freeze

    SUCCESS = [ 0, "".freeze ].freeze

    PIDFILE_LOCATION = "/var/run/automate-liveness-agent.pid".freeze

    WRITE_MODE = "w".freeze

    attr_reader :argv
    attr_reader :config_path
    attr_reader :config
    attr_reader :logger

    def self.run(argv)
      new(argv).run
    end

    def initialize(argv)
      @argv = argv
      @config_path = nil
      @config = Config.new(nil)
      @logger = nil
      @pidfile_handle = nil
    end

    def run
      Pipeline.new(self).
        run(:handle_argv).
        run(:load_config).
        run(:set_privileges).
        run(:setup_logger).
        run(:send_keepalives).
        finish
    end

    def handle_argv
      case argv.size
      when 0
        SUCCESS
      when 1
        if %w{ -h --help help }.include?(argv[0])
          [1, USAGE]
        else
          @config_path = argv[0]
          SUCCESS
        end
      else
        [1, USAGE]
      end
    end

    def load_config
      @config = Config.load(config_path)
      SUCCESS
    rescue ConfigError => e
      [ 1, e.to_s ]
    end

    def set_privileges
      unless config.scheduled_task_mode
        @pidfile_handle = File.open(PIDFILE_LOCATION, WRITE_MODE, 0644)
      end
      unless config.unprivileged_gid.nil?
        Process.gid = config.unprivileged_gid
      end
      unless config.unprivileged_uid.nil?
        Process.uid = config.unprivileged_uid
      end
      SUCCESS
    rescue Errno::EACCES
      msg = "Unable to open pidfile at #{PIDFILE_LOCATION} (current uid: #{Process.uid})"
      [ 1, msg ]
    rescue Errno::EPERM
      msg = "You must run as root to change privileges, or you can set unprivileged_uid and unprivileged_gid to null to disable privilege changes"
      [ 1, msg ]
    end

    # This intentionally comes after #set_privileges. Depending on config and
    # system state, the logger may create logfiles; we must create the files as
    # the lower privileged user or else we won't have permissions to rotate them.
    def setup_logger
      @logger = config.setup_logger
      SUCCESS
    rescue ConfigError => e
      [ 1, e.to_s ]
    end

    def send_keepalives
      a = LivenessUpdateSender.new(config, logger)
      if config.scheduled_task_mode
        a.update
      else
        Process.daemon
        if @pidfile_handle
         @pidfile_handle.write(Process.pid)
         @pidfile_handle.close
        end
        a.main_loop
      end
      SUCCESS
    rescue ConfigError => e
      [ 1, e.to_s ]
    end

  end

end
