require "option_parser"
require "json"
require "base64"
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
      password_stdin = false
      config_path = nil
      query = nil
      export_path = nil
      import_path = nil
      output_format = "plain"
      verbose = false
      quiet = false
      confirm = false
      list_backends_flag = false
      disable_flag = false
      keyring_backend = nil
      keyring_path = nil
      config_key = nil
      config_value = nil
      get_mode = "password"

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: keyring_cr [command] [options]"
        opts.separator ""
        opts.separator "Commands:"
        opts.separator "  get           Get a password"
        opts.separator "  set           Set a password"
        opts.separator "  update        Update a password"
        opts.separator "  delete        Delete a password"
        opts.separator "  list          List all credentials"
        opts.separator "  search        Search credentials"
        opts.separator "  export        Export credentials"
        opts.separator "  import        Import credentials"
        opts.separator "  config        Manage configuration"
        opts.separator "  backend       Manage backends"
        opts.separator "  generate-key  Generate an encryption key"
        opts.separator "  completion    Generate shell completion script"
        opts.separator "  diagnose      Show diagnostic information"
        opts.separator ""
        opts.separator "Options:"

        opts.on("-s NAME", "--service=NAME", "Service name") { |service_name| service = service_name }
        opts.on("-u USER", "--username=USER", "Username") { |user| username = user }
        opts.on("-p PASS", "--password=PASS", "Password") { |pass| password = pass }
        opts.on("--password-stdin", "Read password from stdin") { password_stdin = true }
        opts.on("-c PATH", "--config=PATH", "Config file path") { |config| config_path = config }
        opts.on("-q QUERY", "--query=QUERY", "Search query") { |search_query| query = search_query }
        opts.on("-f FILE", "--file=FILE", "Import/export file path") { |file_path| export_path = import_path = file_path }
        opts.on("--output=FORMAT", "Output format: plain or json") { |format| output_format = format }
        opts.on("--mode=MODE", "Get mode: password or creds") { |mode| get_mode = mode }
        opts.on("--verbose", "Enable verbose logging") { verbose = true }
        opts.on("--quiet", "Suppress non-error output") { quiet = true }
        opts.on("--confirm", "Require confirmation for destructive operations") { confirm = true }
        opts.on("--list-backends", "List available keyring backends and exit") { list_backends_flag = true }
        opts.on("--disable", "Disable keyring and exit") { disable_flag = true }
        opts.on("-b BACKEND", "--keyring-backend=BACKEND", "Specify keyring backend by name") { |backend| keyring_backend = backend }
        opts.on("--keyring-path=PATH", "Path to keyring data/config directory") { |path| keyring_path = path }
        opts.on("--print-completion=SHELL", "Print shell completion script (bash or zsh)") do |shell|
          out_puts generate_completion(shell)
          terminate(0)
        end
        opts.on("-k KEY", "--key=KEY", "Config key") { |key| config_key = key }
        opts.on("--value=VALUE", "Config value (for config set)") { |val| config_value = val }
        opts.on("-h", "--help", "Show this help") do
          out_puts opts
          terminate(0)
        end
        opts.on("--version", "Show version") do
          out_puts "Keyring version #{VERSION}"
          terminate(0)
        end
      end

      begin
        parser.parse(args)

        # Extract command from first positional argument (parse modifies args in-place)
        command = args.empty? ? nil : args.shift

        # Save remaining positional sub-args for commands that need them
        sub_args = args

        # Handle standalone flags (no command needed)
        if keyring_path
          ENV["XDG_DATA_HOME"] = keyring_path
          ENV["XDG_CONFIG_HOME"] = keyring_path
        end

        if list_backends_flag
          Keyring.new.list_available_backends.each { |name| out_puts name }
          terminate(0)
        end

        if disable_flag
          ::Keyring.disable
          terminate(0)
        end

        # If no command, show help and exit 0
        if command.nil?
          out_puts parser
          terminate(0)
        end

        # Set log level for verbose/quiet via config
        if verbose
          ENV["KEYRING_LOG_LEVEL"] = "DEBUG"
        elsif quiet
          ENV["KEYRING_LOG_LEVEL"] = "ERROR"
        end

        keyring = if backend_name = keyring_backend
                    k = Keyring.new(config_path)
                    k.switch_to_backend(backend_name)
                    k
                  else
                    Keyring.new(config_path)
                  end

        case command
        when "get"
          if get_mode == "creds"
            check_required_args(service: service)
            s = service.as(String)
            u = username
            if cred = keyring.get_credential(s, u || "")
              if output_format == "json"
                out_puts({"service" => s, "username" => cred.username, "password" => cred.password}.to_json)
              else
                out_puts cred.username
                out_puts cred.password
              end
            else
              err_puts "No credential found for #{s}".colorize(:red)
              terminate(1)
            end
          else
            check_required_args(service: service, username: username)
            s = service.as(String)
            u = username.as(String)
            if found_password = keyring.get_password(s, u)
              if output_format == "json"
                out_puts({"service" => s, "username" => u, "password" => found_password}.to_json)
              else
                out_puts found_password
              end
            else
              err_puts "No password found for #{s}:#{u}".colorize(:red)
              terminate(1)
            end
          end
        when "set"
          check_required_args(service: service, username: username)
          s = service.as(String)
          u = username.as(String)
          password = resolve_password(password, password_stdin)
          keyring.set_password(s, u, password.as(String))
          out_puts "Password stored successfully".colorize(:green) unless quiet
        when "update"
          check_required_args(service: service, username: username)
          s = service.as(String)
          u = username.as(String)
          password = resolve_password(password, password_stdin)
          keyring.update_password(s, u, password.as(String))
          out_puts "Password updated successfully".colorize(:green) unless quiet
        when "delete"
          check_required_args(service: service, username: username)
          s = service.as(String)
          u = username.as(String)
          if confirm
            out_print "Are you sure you want to delete #{s}:#{u}? [y/N] "
            answer = @@password_provider ? "y" : STDIN.gets.try(&.chomp).try(&.downcase)
            terminate(0) unless answer == "y" || answer == "yes"
          end
          keyring.delete_password(s, u)
          out_puts "Password deleted successfully".colorize(:green) unless quiet
        when "list"
          creds = keyring.list_credentials
          if output_format == "json"
            out_puts creds.to_json
          elsif creds.empty?
            out_puts "No credentials found".colorize(:yellow)
          else
            out_puts "Credentials:".colorize(:cyan)
            creds.each do |entry|
              out_puts "  #{entry.service} - #{entry.username}".colorize(:white)
            end
          end
        when "search"
          check_required_args(query: query)
          q = query.as(String)
          results = keyring.search(q)
          if output_format == "json"
            out_puts results.to_json
          elsif results.empty?
            out_puts "No matching credentials found".colorize(:yellow)
          else
            out_puts "Search results:".colorize(:cyan)
            results.each do |result|
              out_puts "  #{result.service} - #{result.username}".colorize(:white)
            end
          end
        when "export"
          check_required_args(file: export_path)
          f = export_path.as(String)
          keyring.export_credentials(f)
          out_puts "Credentials exported to #{f}".colorize(:green) unless quiet
        when "import"
          check_required_args(file: import_path)
          f = import_path.as(String)
          keyring.import_credentials(f)
          out_puts "Credentials imported from #{f}".colorize(:green) unless quiet
        when "config"
          sub_action = sub_args[0]? || "show"
          case sub_action
          when "show"
            cfg = keyring.config
            if output_format == "json"
              out_puts({
                "preferred_backend" => cfg.preferred_backend,
                "backend_priority"  => cfg.backend_priority,
                "default_service"   => cfg.default_service,
                "encrypt_passwords" => cfg.encrypt_passwords?,
                "log_level"         => cfg.log_level,
                "log_file"          => cfg.log_file,
              }.to_json)
            else
              out_puts "preferred_backend: #{cfg.preferred_backend || "(auto)"}".colorize(:cyan)
              out_puts "backend_priority:  #{cfg.backend_priority.try(&.join(", ")) || "(default)"}"
              out_puts "default_service:   #{cfg.default_service || "(none)"}"
              out_puts "encrypt_passwords: #{cfg.encrypt_passwords?}"
              out_puts "log_level:         #{cfg.log_level}"
              out_puts "log_file:          #{cfg.log_file || "(none)"}"
            end
          when "set"
            k = config_key
            v = config_value
            unless k && v
              err_puts "ERROR: --key and --value are required for config set".colorize(:red)
              terminate(1)
            end
            keyring.config.set_property(k, v)
            keyring.config.save
            out_puts "Config #{config_key} set to #{config_value}".colorize(:green) unless quiet
          else
            err_puts "ERROR: Unknown config sub-command: #{sub_action}".colorize(:red)
            err_puts "Available: show, set"
            terminate(1)
          end
        when "backend"
          sub_action = sub_args[0]? || "list"
          case sub_action
          when "list"
            backends = keyring.list_available_backends
            current = keyring.backend.class.name
            if output_format == "json"
              out_puts backends.map { |name| {"name" => name, "active" => name == current}.to_json }.to_json
            elsif backends.empty?
              out_puts "No backends available".colorize(:yellow)
            else
              out_puts "Available backends:".colorize(:cyan)
              backends.each do |name|
                marker = name == current ? " *" : "  "
                out_puts "#{marker} #{name}".colorize(name == current ? :green : :white)
              end
            end
          when "switch"
            target = sub_args[1]?
            unless target
              err_puts "ERROR: backend name required".colorize(:red)
              terminate(1)
            end
            new_backend = keyring.switch_to_backend(target)
            out_puts "Switched to backend: #{new_backend.class.name}".colorize(:green) unless quiet
          else
            err_puts "ERROR: Unknown backend sub-command: #{sub_action}".colorize(:red)
            err_puts "Available: list, switch"
            terminate(1)
          end
        when "generate-key"
          key = Encryption.generate_key
          out_puts key
        when "completion"
          shell = sub_args[0]? || "bash"
          out_puts generate_completion(shell)
        when "diagnose"
          root = Platform.config_root
          path = root + "/config.yml"
          if File.exists?(path)
            out_puts "config path: #{path}"
          else
            out_puts "config path: #{path} (absent)"
          end
          out_puts "data root: #{Platform.data_root}"
        else
          err_puts "ERROR: No command specified".colorize(:red)
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

    private def self.resolve_password(password, password_stdin) : String?
      return password if password

      result = if password_stdin
                 if provider = @@password_provider
                   provider.call
                 else
                   STDIN.gets
                 end
               else
                 out_print "Enter password: "
                 val = read_password
                 out_puts ""
                 val
               end
      strip_last_newline(result)
    end

    private def self.strip_last_newline(str : String?) : String?
      return unless str
      str.ends_with?('\n') ? str[0..-2] : str
    end

    private def self.check_required_args(**args)
      args.each do |name, value|
        if value.nil?
          err_puts "ERROR: #{name} is required".colorize(:red)
          terminate(1)
        end
      end
    end

    private def self.generate_completion(shell : String) : String
      case shell
      when "bash"
        <<-BASH
_keyring_cr_completion() {
  local cur prev words cword
  _init_completion || return
  COMMANDS="get set update delete list search export import config backend generate-key diagnose"

  case $prev in
    -s|--service) COMPREPLY=() ; return ;;
    -u|--username) COMPREPLY=() ; return ;;
    -f|--file) _filedir ; return ;;
    -c|--config) _filedir ; return ;;
    --output) COMPREPLY=( $(compgen -W "plain json" -- "$cur") ) ; return ;;
    config)
      COMPREPLY=( $(compgen -W "show set" -- "$cur") )
      return ;;
    backend)
      COMPREPLY=( $(compgen -W "list switch" -- "$cur") )
      return ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
      return ;;
  esac

  if [[ $cur == -* ]]; then
    COMPREPLY=( $(compgen -W "--service --username --password --password-stdin --config --query --file --output --mode --verbose --quiet --help --version --confirm --list-backends --disable --keyring-backend --key --value" -- "$cur") )
  else
    COMPREPLY=( $(compgen -W "$COMMANDS" -- "$cur") )
  fi
}
complete -F _keyring_cr_completion keyring_cr
BASH
      when "zsh"
        <<-ZSH
#compdef keyring_cr

_keyring_cr() {
  local -a commands
  commands=(
    'get:Get a password'
    'set:Set a password'
    'update:Update a password'
    'delete:Delete a password'
    'list:List all credentials'
    'search:Search credentials'
    'export:Export credentials'
    'import:Import credentials'
    'config:Manage configuration'
    'backend:Manage backends'
    'generate-key:Generate an encryption key'
    'diagnose:Show diagnostic information'
    'completion:Generate shell completion script'
  )
  _describe -t commands 'keyring_cr commands' commands
}
_keyring_cr
ZSH
      else
        "# Unsupported shell: #{shell}"
      end
    end
  end
end

Keyring::CLI.run if PROGRAM_NAME.ends_with?("keyring_cr")
