require "log"

module Keyring
  Log = ::Log.for(self)

  def self.setup_logging(config : Config)
    backend = if path = config.log_file
      ::Log::IOBackend.new(File.open(path, "a"))
    else
      ::Log::IOBackend.new
    end

    level = ::Log::Severity.parse(config.log_level)
    ::Log.setup do |c|
      c.bind "*", level, backend
    end
  end
end
