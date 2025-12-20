require "./src/keyring"

puts "Testing FileBackend"
puts "=" * 50

storage_path = "/tmp/test_keyring_#{Time.utc.to_unix}.enc.json"
key = Keyring::Encryption.generate_key

backend = Keyring::FileBackend.new(storage_path, key)

puts "\n1. Testing set_password..."
backend.set_password("test_app", "user1", "password123")
puts "✓ Password stored"

puts "\n2. Testing get_password..."
password = backend.get_password("test_app", "user1")
if password == "password123"
  puts "✓ Password retrieved: #{password}"
else
  puts "✗ Wrong password"
  exit 1
end

puts "\n3. Testing persistence..."
backend2 = Keyring::FileBackend.new(storage_path, key)
password = backend2.get_password("test_app", "user1")
if password == "password123"
  puts "✓ Password persisted across instances"
else
  puts "✗ Persistence failed"
  exit 1
end

puts "\n4. Testing multiple credentials..."
backend.set_password("app1", "user1", "pass1")
backend.set_password("app2", "user2", "pass2")
backend.set_password("app3", "user3", "pass3")
credentials = backend.list_credentials
puts "✓ Stored #{credentials.size} credentials"

puts "\n5. Testing encryption..."
raw_content = File.read(storage_path)
if raw_content.includes?("password123") || raw_content.includes?("user1")
  puts "✗ Data not encrypted!"
  exit 1
else
  puts "✓ Data is encrypted"
end

puts "\n6. Testing delete..."
backend.delete_password("test_app", "user1")
if backend.get_password("test_app", "user1").nil?
  puts "✓ Password deleted"
else
  puts "✗ Delete failed"
  exit 1
end

puts "\n7. Testing file permissions..."
{% unless flag?(:windows) %}
  stat = File.info(storage_path)
  perms = stat.permissions.value & 0o777
  if perms == 0o600
    puts "✓ File permissions correct (0600)"
  else
    puts "✗ Wrong permissions: #{perms.to_s(8)}"
    exit 1
  end
{% else %}
  puts "⏭ Skipping permission test on Windows"
{% end %}

puts "\n8. Cleanup..."
File.delete(storage_path) if File.exists?(storage_path)
File.delete("#{storage_path}.lock") if File.exists?("#{storage_path}.lock")
key_path = File.join(File.dirname(storage_path), ".keyring_key")
File.delete(key_path) if File.exists?(key_path)
puts "✓ Cleaned up"

puts "\n" + "=" * 50
puts "All FileBackend tests passed! ✓"
puts "=" * 50
