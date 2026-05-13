require "./src/keyring"

puts "Testing list_credentials on macOS"
puts "=" * 50

keyring = Keyring::Keyring.new

# Create some test credentials
test_prefix = "list_test_#{Time.utc.to_unix}"

puts "\n1. Creating test credentials..."
keyring.set_password("#{test_prefix}_app1", "user1", "pass1")
keyring.set_password("#{test_prefix}_app2", "user2", "pass2")
keyring.set_password("#{test_prefix}_app3", "user3", "pass3")
puts "✓ Created 3 test credentials"

puts "\n2. Listing all credentials..."
begin
  credentials = keyring.list_credentials
  puts "✓ Found #{credentials.size} total credentials in keychain"

  # Filter to our test credentials
  test_creds = credentials.select(&.service.starts_with?(test_prefix))
  puts "✓ Found #{test_creds.size} test credentials"

  if test_creds.size == 3
    puts "✓ All 3 test credentials found!"

    test_creds.each do |cred|
      puts "  - Service: #{cred.service}, Username: #{cred.username}"
    end
  else
    puts "✗ Expected 3 credentials, found #{test_creds.size}"
    exit 1
  end
rescue ex
  puts "✗ Failed to list credentials: #{ex.message}"
  puts ex.backtrace.join("\n")
  exit 1
end

puts "\n3. Testing search functionality..."
results = keyring.search(test_prefix)
puts "✓ Search found #{results.size} credentials matching '#{test_prefix}'"

puts "\n4. Cleaning up..."
keyring.delete_password("#{test_prefix}_app1", "user1")
keyring.delete_password("#{test_prefix}_app2", "user2")
keyring.delete_password("#{test_prefix}_app3", "user3")
puts "✓ Cleaned up test credentials"

puts "\n5. Verifying cleanup..."
credentials = keyring.list_credentials
remaining = credentials.select(&.service.starts_with?(test_prefix))
if remaining.empty?
  puts "✓ All test credentials removed"
else
  puts "✗ #{remaining.size} credentials still remain"
  exit 1
end

puts "\n" + "=" * 50
puts "list_credentials test passed! ✓"
puts "=" * 50
