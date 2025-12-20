require "option_parser"
require "./keyring"
require "colorize"

module Keyring
  class CLI
    class FinishedCLI < Exception
      getter code : Int32

      def initialize(@code : Int32 = 0); end
    end

    @@out : IO = STDOUT
    @@err : IO = STDERR
    @@password_provider : Proc(String?)? = nil

    def self.set_io(out_io : IO, err_io : IO)
      @@out = out_io
      @@err = err_io
    end

    def self.reset_io
      @@out = STDOUT
      @@err = STDERR
    end

    def self.set_password_provider(&block : -> String?)
      @@password_provider = block
    end

    def self.reset_password_provider
      @@password_provider = nil
    end

    private def self.out_puts(obj)
      @@out.puts obj
    end

    private def self.out_print(obj)
      @@out.print obj
    end

    private def self.err_puts(obj)
      @@err.puts obj
    end

    private def self.read_password : String?
      if provider = @@password_provider
        return provider.call
      end
      STDIN.noecho(&.gets).try(&.chomp)
    end

    private def self.terminate(code : Int32 = 0)
      raise FinishedCLI.new(code) if ENV["KEYRING_TEST_CLI"]?
      exit(code)
    end

    # ameba:disable Metrics/CyclomaticComplexity
    def self.run(args = ARGV)
      command = nil
      service = nil
      username = nil
      password = nil
      config_path = nil
      query = nil
      export_path = nil
      import_path = nil

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: keyring [command] [options]"

        opts.on("get", "Get a password") { command = "get" }
        opts.on("set", "Set a password") { command = "set" }
        opts.on("delete", "Delete a password") { command = "delete" }
        opts.on("list", "List all credentials") { command = "list" }
        opts.on("search", "Search credentials") { command = "search" }
        opts.on("export", "Export credentials") { command = "export" }
        opts.on("import", "Import credentials") { command = "import" }

        opts.on("-s NAME", "--service=NAME", "Service name") { |service_name| service = service_name }
        opts.on("-u USER", "--username=USER", "Username") { |user| username = user }
        opts.on("-p PASS", "--password=PASS", "Password") { |pass| password = pass }
        opts.on("-c PATH", "--config=PATH", "Config file path") { |config| config_path = config }
        opts.on("-q QUERY", "--query=QUERY", "Search query") { |search_query| query = search_query }
        opts.on("-f FILE", "--file=FILE", "Import/export file path") { |file_path| export_path = import_path = file_path }
        opts.on("-h", "--help", "Show this help") do
          out_puts opts
          terminate(0)
        end
        opts.on("-v", "--version", "Show version") do
          out_puts "Keyring version #{VERSION}"
          terminate(0)
        end

        opts.invalid_option do |flag|
          err_puts "ERROR: #{flag} is not a valid option."
          err_puts opts
          terminate(1)
        end
      end

      begin
        parser.parse(args)
        # If no command and no args, show help and exit 0
        if args.empty? && command.nil?
          out_puts parser
          terminate(0)
        end
        keyring = Keyring.new(config_path)

        case command
        when "get"
          check_required_args(service: service, username: username)
          s = service.as(String)
          u = username.as(String)
          if password = keyring.get_password(s, u)
            out_puts password
          else
            err_puts "No password found".colorize(:red)
            terminate(1)
          end
        when "set"
          check_required_args(service: service, username: username)
          s = service.as(String)
          u = username.as(String)
          unless password
            out_print "Enter password: "
            password = read_password
            out_puts ""
          end
          keyring.set_password(s, u, password.as(String))
          out_puts "Password stored successfully".colorize(:green)
        when "delete"
          check_required_args(service: service, username: username)
          s = service.as(String)
          u = username.as(String)
          keyring.delete_password(s, u)
          out_puts "Password deleted successfully".colorize(:green)
        when "list"
          creds = keyring.list_credentials
          if creds.empty?
            out_puts "No credentials found".colorize(:yellow)
          else
            out_puts "Credentials:".colorize(:cyan)
            creds.each do |cred|
              out_puts "  #{cred.service} - #{cred.username}".colorize(:white)
            end
          end
        when "search"
          check_required_args(query: query)
          q = query.as(String)
          results = keyring.search(q)
          if results.empty?
            out_puts "No matching credentials found".colorize(:yellow)
          else
            out_puts "Search results:".colorize(:cyan)
            results.each do |cred|
              out_puts "  #{cred.service} - #{cred.username}".colorize(:white)
            end
          end
        when "export"
          check_required_args(file: export_path)
          f = export_path.as(String)
          keyring.export_credentials(f)
          out_puts "Credentials exported successfully".colorize(:green)
        when "import"
          check_required_args(file: import_path)
          f = import_path.as(String)
          keyring.import_credentials(f)
          out_puts "Credentials imported successfully".colorize(:green)
        else
          err_puts "ERROR: No command specified"
          err_puts parser
          terminate(1)
        end
      rescue ex : OptionParser::InvalidOption
        err_puts "ERROR: #{ex.message}".colorize(:red)
        err_puts parser
        terminate(1)
      rescue ex : Error
        err_puts "ERROR: #{ex.message}".colorize(:red)
        terminate(1)
      end
    end

    private def self.check_required_args(**args)
      args.each do |name, value|
        if value.nil?
          err_puts "ERROR: #{name} is required".colorize(:red)
          terminate(1)
        end
      end
    end
  end
end

Keyring::CLI.run
