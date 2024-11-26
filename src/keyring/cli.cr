 require "option_parser"
 require "./keyring"
 require "colorize"

 module Keyring
   class CLI
     def self.run(args = ARGV)
       command = nil
       service = nil
       username = nil
       password = nil
       config_path = nil
       query = nil
       export_path = nil
       import_path = nil

       parser = OptionParser.new do |parser|
         parser.banner = "Usage: keyring [command] [options]"

         parser.on("get", "Get a password") { command = "get" }
         parser.on("set", "Set a password") { command = "set" }
         parser.on("delete", "Delete a password") { command = "delete" }
         parser.on("list", "List all credentials") { command = "list" }
         parser.on("search", "Search credentials") { command = "search" }
         parser.on("export", "Export credentials") { command = "export" }
         parser.on("import", "Import credentials") { command = "import" }

         parser.on("-s NAME", "--service=NAME", "Service name") { |s| service = s }
         parser.on("-u USER", "--username=USER", "Username") { |u| username = u }
         parser.on("-p PASS", "--password=PASS", "Password") { |p| password = p }
         parser.on("-c PATH", "--config=PATH", "Config file path") { |c| config_path = c }
         parser.on("-q QUERY", "--query=QUERY", "Search query") { |q| query = q }
         parser.on("-f FILE", "--file=FILE", "Import/export file path") { |f| export_path = import_path = f }
         parser.on("-h", "--help", "Show this help") do
           puts parser
           exit
         end
         parser.on("-v", "--version", "Show version") do
           puts "Keyring version #{VERSION}"
           exit
         end

         parser.invalid_option do |flag|
           STDERR.puts "ERROR: #{flag} is not a valid option."
           STDERR.puts parser
           exit(1)
         end
       end

       begin
         parser.parse(args)
         keyring = Keyring.new(config_path)

         case command
         when "get"
           check_required_args(service: service, username: username)
           if password = keyring.get_password(service, username)
             puts password
           else
             STDERR.puts "No password found".colorize(:red)
             exit(1)
           end

         when "set"
           check_required_args(service: service, username: username)
           unless password
             print "Enter password: "
             password = STDIN.noecho(&.gets).try(&.chomp)
             puts
           end
           keyring.set_password(service, username, password.not_nil!)
           puts "Password stored successfully".colorize(:green)

         when "delete"
           check_required_args(service: service, username: username)
           keyring.delete_password(service, username)
           puts "Password deleted successfully".colorize(:green)

         when "list"
           creds = keyring.list_credentials
           if creds.empty?
             puts "No credentials found".colorize(:yellow)
           else
             puts "Credentials:".colorize(:cyan)
             creds.each do |cred|
               puts "  #{cred.service} - #{cred.username}".colorize(:white)
             end
           end

         when "search"
           check_required_args(query: query)
           results = keyring.search(query)
           if results.empty?
             puts "No matching credentials found".colorize(:yellow)
           else
             puts "Search results:".colorize(:cyan)
             results.each do |cred|
               puts "  #{cred.service} - #{cred.username}".colorize(:white)
             end
           end

         when "export"
           check_required_args(file: export_path)
           keyring.export_credentials(export_path)
           puts "Credentials exported successfully".colorize(:green)

         when "import"
           check_required_args(file: import_path)
           keyring.import_credentials(import_path)
           puts "Credentials imported successfully".colorize(:green)

         else
           STDERR.puts "ERROR: No command specified"
           STDERR.puts parser
           exit(1)
         end

       rescue ex : OptionParser::InvalidOption
         STDERR.puts "ERROR: #{ex.message}".colorize(:red)
         STDERR.puts parser
         exit(1)
       rescue ex : Keyring::Error
         STDERR.puts "ERROR: #{ex.message}".colorize(:red)
         exit(1)
       end
     end

     private def self.check_required_args(**args)
       args.each do |name, value|
         if value.nil?
           STDERR.puts "ERROR: #{name} is required".colorize(:red)
           exit(1)
         end
       end
     end
   end
 end
