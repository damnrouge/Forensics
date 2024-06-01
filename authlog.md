# Understanding `auth.log`

## Auth Log Format

<timestamp> <hostname> <service_name>[<process_id>]: <message>

The `auth.log` file in Linux systems logs all authentication-related events, such as user logins, failed login attempts, and other relevant security events. Each entry in the `auth.log` file consists of several fields providing details about the event.

## Breakdown of Fields

1. **Timestamp**: Indicates the date and time when the event occurred.
2. **Hostname**: The name of the host (server) where the event took place.
3. **Service**: The name of the service or daemon generating the log entry (e.g., `sshd`, `CRON`).
4. **Process ID**: The unique identifier for the process generating the log entry.
5. **Message**: A detailed message describing the event, including user information and the nature of the event.

## Example Entries and Their Meanings

### Failed Login Attempt
Jun 1 12:05:01 server01 sshd[12850]: Failed password for invalid user test from 192.168.1.100 port 40022 ssh2

- **Timestamp**: Jun  1 12:05:01
- **Hostname**: server01
- **Service**: sshd
- **Process ID**: 12850
- **Message**: Failed password for invalid user test from 192.168.1.100 port 40022 ssh2

This entry indicates a failed login attempt using the username `test` from the IP address `192.168.1.100`.

### Successful Login
Jun 1 13:05:01 server01 sshd[13230]: Accepted password for user from 192.168.1.100 port 40065 ssh2

- **Timestamp**: Jun  1 13:05:01
- **Hostname**: server01
- **Service**: sshd
- **Process ID**: 13230
- **Message**: Accepted password for user from 192.168.1.100 port 40065 ssh2

This entry indicates a successful login for the user `user` from the IP address `192.168.1.100`.

### CRON Job Execution
Jun 1 12:01:01 server01 CRON[12843]: pam_unix(cron:session): session opened for user root by (uid=0)
Jun 1 12:01:01 server01 CRON[12843]: pam_unix(cron:session): session closed for user root

- **Timestamp**: Jun  1 12:01:01
- **Hostname**: server01
- **Service**: CRON
- **Process ID**: 12843
- **Message**: 
  - `pam_unix(cron:session): session opened for user root by (uid=0)`: Indicates that a CRON job session for the user `root` has started.
  - `pam_unix(cron:session): session closed for user root`: Indicates that the CRON job session for the user `root` has ended.

## Key Points to Note

- **Failed Login Attempts**: Frequent failed login attempts, especially from the same IP address, can indicate a brute force attack.
- **Successful Logins**: Regular monitoring of successful logins helps ensure that only authorized users are accessing the system.
- **CRON Jobs**: Regular CRON job entries indicate scheduled tasks running as expected. Unusual CRON jobs might signify unauthorized or malicious activities.

## Additional Resources

- [Linux `auth.log` Documentation](https://linux.die.net/man/3/syslog)
- [Understanding SSH Logs](https://www.ssh.com/academy/ssh/logging)
- [CRON Job Basics](https://www.geeksforgeeks.org/cron-command-in-linux-with-examples/)
- [Linux Security and Monitoring](https://www.tecmint.com/linux-server-security-tips/)

## Filtering Specific Entries
# Filter for failed login attempts
grep "Failed password" /var/log/auth.log

# Filter for successful login attempts
grep "Accepted password" /var/log/auth.log

# Filter for CRON job executions
grep CRON /var/log/auth.log

## Counting Specific Events

# Count the number of failed login attempts
grep -c "Failed password" /var/log/auth.log

# Count the number of successful login attempts
grep -c "Accepted password" /var/log/auth.log

# Count the number of CRON job executions
grep -c CRON /var/log/auth.log

## Analyzing Failed Login Attempts

# Extract and sort IP addresses of failed login attempts
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# Extract and sort usernames used in failed login attempts
grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr

## Example Commands and Their Outputs

# Example: Viewing the last 20 lines of auth.log
tail -n 20 /var/log/auth.log

# Example: Filtering for failed login attempts and displaying the last 10
grep "Failed password" /var/log/auth.log | tail -n 10

# Example: Counting the number of successful login attempts
grep -c "Accepted password" /var/log/auth.log

# Example: Extracting and sorting IP addresses of failed login attempts
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
