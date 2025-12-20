require "./src/keyring"

puts "Testing Development Mode (allow_any_access)"
puts "=" * 50

# Enable development mode
Keyring::MacOsKeyChainBackend.allow_any_access = true
puts "✓ Development mode enabled"

keyring = Keyring::Keyring.new

test_service = "dev_mode_test_#{Time.utc.to_unix}"
test_username = "dev_user"
test_password = "dev_password_123"

puts "\nStoring password (should create with -A flag)..."
keyring.set_password(test_service, test_username, test_password)
puts "✓ Password stored"

puts "\nRetrieving password..."
retrieved = keyring.get_password(test_service, test_username)
if retrieved == test_password
  puts "✓ Password retrieved: #{retrieved}"
else
  puts "✗ Password mismatch!"
  exit 1
end

puts "\nCleaning up..."
keyring.delete_password(test_service, test_username)
puts "✓ Cleaned up"

puts "\n" + "=" * 50
puts "Development mode test passed!"
puts "Credentials created with -A flag are accessible by any app."
puts "=" * 50
