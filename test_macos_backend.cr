require "./src/keyring"

# Test script for macOS Keychain backend
puts "Testing macOS Keychain Backend"
puts "=" * 50

keyring = Keyring::Keyring.new

test_service = "keyring_test_app"
test_username = "test_user_#{Time.utc.to_unix}"
test_password = "test_password_123!"

puts "\n1. Testing backend availability..."
if keyring.backend.is_a?(Keyring::MacOsKeyChainBackend)
  puts "✓ Using MacOSKeyChainBackend"
else
  puts "✗ Not using MacOSKeyChainBackend: #{keyring.backend.class}"
  exit 1
end

puts "\n2. Testing set_password..."
begin
  keyring.set_password(test_service, test_username, test_password)
  puts "✓ Password stored successfully"
rescue ex
  puts "✗ Failed to store password: #{ex.message}"
  exit 1
end

puts "\n3. Testing get_password..."
begin
  retrieved = keyring.get_password(test_service, test_username)
  if retrieved == test_password
    puts "✓ Password retrieved correctly: #{retrieved}"
  else
    puts "✗ Retrieved password doesn't match!"
    puts "  Expected: #{test_password}"
    puts "  Got: #{retrieved}"
    exit 1
  end
rescue ex
  puts "✗ Failed to retrieve password: #{ex.message}"
  exit 1
end

puts "\n4. Testing get_credential..."
begin
  cred = keyring.backend.get_credential(test_service, test_username)
  if cred && cred.service == test_service && cred.username == test_username
    puts "✓ Credential retrieved correctly"
    puts "  Service: #{cred.service}"
    puts "  Username: #{cred.username}"
  else
    puts "✗ Credential data incorrect"
    exit 1
  end
rescue ex
  puts "✗ Failed to get credential: #{ex.message}"
  exit 1
end

puts "\n5. Testing password update..."
begin
  new_password = "updated_password_456!"
  keyring.set_password(test_service, test_username, new_password)
  retrieved = keyring.get_password(test_service, test_username)
  if retrieved == new_password
    puts "✓ Password updated successfully"
  else
    puts "✗ Password update failed"
    exit 1
  end
rescue ex
  puts "✗ Failed to update password: #{ex.message}"
  exit 1
end

puts "\n6. Testing delete_password..."
begin
  keyring.delete_password(test_service, test_username)
  puts "✓ Password deleted successfully"
rescue ex
  puts "✗ Failed to delete password: #{ex.message}"
  exit 1
end

puts "\n7. Verifying deletion..."
begin
  retrieved = keyring.get_password(test_service, test_username)
  if retrieved.nil?
    puts "✓ Password confirmed deleted"
  else
    puts "✗ Password still exists after deletion!"
    exit 1
  end
rescue ex
  puts "✗ Error verifying deletion: #{ex.message}"
  exit 1
end

puts "\n8. Testing non-existent password retrieval..."
begin
  retrieved = keyring.get_password("nonexistent_service", "nonexistent_user")
  if retrieved.nil?
    puts "✓ Correctly returns nil for non-existent password"
  else
    puts "✗ Should return nil for non-existent password"
    exit 1
  end
rescue ex
  puts "✗ Unexpected error: #{ex.message}"
  exit 1
end

puts "\n9. Testing delete non-existent password..."
begin
  keyring.delete_password("nonexistent_service", "nonexistent_user")
  puts "✗ Should have raised error for non-existent password"
  exit 1
rescue Keyring::PasswordDeleteError
  puts "✓ Correctly raises error for non-existent password"
rescue ex
  puts "✗ Wrong exception type: #{ex.class}"
  exit 1
end

puts "\n" + "=" * 50
puts "All tests passed! ✓"
puts "=" * 50
