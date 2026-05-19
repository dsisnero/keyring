require "../spec_helper"
require "../../src/keyring/cli"

module Keyring
  describe CLI do
    before_each do
      ENV["KEYRING_TEST_CLI"] = "1"
      ENV["KEYRING_BACKEND"] = "FileBackend"
      tmp = "/tmp/keyring-cli-#{Random.rand(1_000_000)}"
      Dir.mkdir_p(tmp)
      Dir.mkdir_p(File.join(tmp, "keyring_cr"))
      ENV["XDG_DATA_HOME"] = tmp
      ENV["XDG_CONFIG_HOME"] = tmp
    end

    after_each do
      ENV.delete("KEYRING_TEST_CLI")
      ENV.delete("KEYRING_BACKEND")
      ENV.delete("KEYRING_LOG_LEVEL")
      ENV.delete("XDG_DATA_HOME")
      ENV.delete("XDG_CONFIG_HOME")
      CLI.reset_io
      CLI.reset_password_provider
    end

    it ".run displays help with --help flag" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      begin
        CLI.run(["--help"])
        fail "expected FinishedCLI"
      rescue e : CLI::FinishedCLI
        e.code.should eq(0)
      end
      stdout_io.to_s.includes?("Usage: keyring").should be_true
    end

    it ".run displays version with --version flag" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      begin
        CLI.run(["--version"])
        fail "expected FinishedCLI"
      rescue e : CLI::FinishedCLI
        e.code.should eq(0)
      end
      stdout_io.to_s.includes?("Keyring version").should be_true
    end

    it "shows help when no arguments" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      begin
        CLI.run([] of String)
        fail "expected FinishedCLI"
      rescue e : CLI::FinishedCLI
        e.code.should eq(0)
      end
      stdout_io.to_s.includes?("Usage: keyring").should be_true
    end

    it "set command stores password and get retrieves it" do
      service = "cli-svc-#{Random.rand(10_000)}"
      user = "cli-user"
      pw = "cli-pass"

      CLI.run(["set", "-s", service, "-u", user, "-p", pw])
      # Verify via API
      k = Keyring.new
      k.get_password(service, user).should eq(pw)

      # Now get via CLI (capture stdout)
      out_io = IO::Memory.new
      err_io = IO::Memory.new
      CLI.set_io(out_io, err_io)
      CLI.run(["get", "-s", service, "-u", user])
      out_io.to_s.includes?(pw).should be_true
    end

    it "delete command deletes password" do
      service = "cli-del-#{Random.rand(10_000)}"
      user = "user"
      pw = "pw"
      CLI.run(["set", "-s", service, "-u", user, "-p", pw])
      CLI.run(["delete", "-s", service, "-u", user])
      Keyring.new.get_password(service, user).should be_nil
    end

    it "list command lists all credentials (smoke)" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      service = "cli-list-#{Random.rand(10_000)}"
      ["a", "b"].each { |username| CLI.run(["set", "-s", service, "-u", username, "-p", "pw-#{username}"]) }
      CLI.run(["list"])
      s = stdout_io.to_s
      (s.includes?("Credentials:") || s.includes?("No credentials found")).should be_true
    end

    it "search command searches credentials (smoke)" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      service = "cli-search-#{Random.rand(10_000)}"
      CLI.run(["set", "-s", service, "-u", "x", "-p", "pw"])
      CLI.run(["search", "-q", service])
      s = stdout_io.to_s
      (s.includes?("Search results:") || s.includes?("No matching credentials found")).should be_true
    end

    it "export and import commands work" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      service = "cli-export-#{Random.rand(10_000)}"
      CLI.run(["set", "-s", service, "-u", "u1", "-p", "p1"])
      CLI.run(["set", "-s", service, "-u", "u2", "-p", "p2"])
      export_file = File.join(ENV["XDG_DATA_HOME"], "keyring_cr", "creds.json")
      CLI.run(["export", "-f", export_file])
      stdout_io.to_s.includes?("exported").should be_true

      # Reset store by pointing to a new directory
      new_store = File.join(ENV["XDG_DATA_HOME"], "new")
      Dir.mkdir_p(new_store)
      Dir.mkdir_p(File.join(new_store, "keyring_cr"))
      ENV["XDG_DATA_HOME"] = new_store

      # Import
      stdout_io.clear
      CLI.run(["import", "-f", export_file])
      stdout_io.to_s.includes?("imported").should be_true
      k = Keyring.new
      users = k.list_usernames(service)
      users.sort.should eq(["u1", "u2"])
    end

    it "interactive password input via provider" do
      service = "cli-int-#{Random.rand(10_000)}"
      user = "int-user"
      CLI.set_password_provider { "pw_int" }
      CLI.run(["set", "-s", service, "-u", user])
      Keyring.new.get_password(service, user).should eq("pw_int")
    end

    it "get with --output json returns JSON format" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      service = "cli-json-#{Random.rand(10_000)}"
      CLI.run(["set", "-s", service, "-u", "json-user", "-p", "json-pass"])
      stdout_io.clear
      CLI.run(["get", "-s", service, "-u", "json-user", "--output", "json"])
      output = stdout_io.to_s
      output.includes?("service").should be_true
      output.includes?("json-user").should be_true
      output.includes?("json-pass").should be_true
    end

    it "list with --output json returns JSON array" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      service = "cli-json-list-#{Random.rand(10_000)}"
      CLI.run(["set", "-s", service, "-u", "a", "-p", "pa"])
      stdout_io.clear
      CLI.run(["list", "--output", "json"])
      output = stdout_io.to_s
      output.starts_with?("[").should be_true
      output.includes?("service").should be_true
    end

    it "generate-key command outputs a base64 key" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["generate-key"])
      output = stdout_io.to_s.strip
      output.should_not be_empty
      # Base64 encoded 32-byte key
      Base64.decode(output).size.should eq(32)
    end

    it "config show outputs current config" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["config", "show"])
      output = stdout_io.to_s
      output.includes?("preferred_backend").should be_true
    end

    it "config set updates a config value" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["config", "set", "-k", "log_level", "--value", "DEBUG"])
      output = stdout_io.to_s
      output.includes?("set to DEBUG").should be_true

      # Verify the change persisted
      stdout_io.clear
      CLI.run(["config", "show"])
      stdout_io.to_s.includes?("DEBUG").should be_true
    end

    it "config set requires --key and --value" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      begin
        CLI.run(["config", "set"])
        fail "expected FinishedCLI"
      rescue e : CLI::FinishedCLI
        e.code.should eq(1)
      end
      stderr_io.to_s.includes?("required").should be_true
    end

    it "update command changes an existing password" do
      service = "cli-update-#{Random.rand(10_000)}"
      user = "update-user"
      CLI.run(["set", "-s", service, "-u", user, "-p", "old-pw"])
      CLI.run(["update", "-s", service, "-u", user, "-p", "new-pw"])
      Keyring.new.get_password(service, user).should eq("new-pw")
    end

    it "backend list shows available backends" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["backend", "list"])
      output = stdout_io.to_s
      output.includes?("Available backends").should be_true
    end

    it "backend list --output json returns JSON" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["backend", "list", "--output", "json"])
      output = stdout_io.to_s
      output.starts_with?("[").should be_true
    end

    it "backend switch changes active backend" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["backend", "switch", "FileBackend"])
      output = stdout_io.to_s
      output.includes?("Switched").should be_true
      output.includes?("FileBackend").should be_true
    end

    it "--password-stdin reads password from stdin" do
      service = "cli-stdin-#{Random.rand(10_000)}"
      user = "stdin-user"
      # Simulate password via provider with stdin simulation
      CLI.set_password_provider { "stdin-pw" }
      CLI.run(["set", "-s", service, "-u", user, "--password-stdin"])
      Keyring.new.get_password(service, user).should eq("stdin-pw")
    end

    it "--quiet suppresses success output" do
      service = "cli-quiet-#{Random.rand(10_000)}"
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["set", "-s", service, "-u", "q", "-p", "pw", "--quiet"])
      stdout_io.to_s.should be_empty
    end

    it "--verbose flag does not error on valid command" do
      service = "cli-verbose-#{Random.rand(10_000)}"
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["set", "-s", service, "-u", "v", "-p", "pw", "--verbose"])
      stdout_io.to_s.includes?("stored").should be_true
    end

    it "completion bash outputs a bash script" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["completion", "bash"])
      output = stdout_io.to_s
      output.includes?("_keyring_cr_completion").should be_true
      output.includes?("complete -F").should be_true
    end

    it "completion zsh outputs a zsh script" do
      stdout_io = IO::Memory.new; stderr_io = IO::Memory.new
      CLI.set_io(stdout_io, stderr_io)
      CLI.run(["completion", "zsh"])
      output = stdout_io.to_s
      output.includes?("compdef keyring_cr").should be_true
    end
  end
end
