require "./src/keyring"

puts "Simple list_credentials test"
puts "Note: You may see permission dialogs - click 'Always Allow'"
puts "=" * 50

keyring = Keyring::Keyring.new

test_service = "simple_list_test_#{Time.utc.to_unix}"

# Create ONE test credential
puts "\nCreating test credential..."
keyring.set_password(test_service, "testuser", "testpass")
puts "✓ Created"

# List credentials
puts "\nListing credentials (may trigger permission dialog)..."
puts "DEBUG: About to call list_credentials..."
credentials = keyring.list_credentials
puts "✓ List returned #{credentials.size} credentials"

# Find our credential
found = credentials.find { |c| c.service == test_service }
if found
  puts "✓ Found our credential!"
  puts "  Service: #{found.service}"
  puts "  Username: #{found.username}"
  puts "  Password: #{found.password}"
else
  puts "✗ Our credential not found"
  puts "Services found: #{credentials.map(&.service).join(", ")}"
end

# Cleanup
keyring.delete_password(test_service, "testuser")
puts "✓ Cleaned up"
