require 'json'
require 'fileutils'
require 'set'
# Color codes for output
COLOR_RED = "\033[31m"
COLOR_YELLOW = "\033[33m"
COLOR_GREEN = "\033[32m"
RESET_TEXT_FORMATTING = "\033[0m"  # Clear all applied styles and reset to default
# Load the vulnerabilities from the JSON files
def load_vulnerabilities(file)
  JSON.parse(File.read(file))
end
# Parse the vulnerabilities and return an array of hashes with required attributes
def parse_vulnerabilities(vulnerabilities_json)
  vulnerabilities_json['Results'].flat_map do |result|
    # Ensure that 'Vulnerabilities' exists and is not nil
    next if result['Vulnerabilities'].nil?
    result['Vulnerabilities'].map do |vuln|
      {
        vulnerability_id: vuln['VulnerabilityID'],
        package_uid: vuln['PkgIdentifier']['UID'],
        target_file: result['Target'],
        severity: vuln['Severity'],
        title: vuln['Title'],
        fixed_version: vuln['FixedVersion'],
        pkg_name: vuln['PkgName'],
        installed_version: vuln['InstalledVersion'],
        cvss_score: vuln['CVSSScore'],
        published_date: vuln['PublishedDate'],
        description: vuln['Description'],
        references: vuln['References'] || []
      }
    end
  end.compact # Remove nil entries from the result
end
# Compare vulnerabilities and return a list of new ones based on VulnerabilityID, PackageUID, and TargetFile
def compare_vulnerabilities(base_vulnerabilities, head_vulnerabilities)
  # Create sets of vulnerability data from base and head
  base_set = base_vulnerabilities.map { |vuln| [vuln[:vulnerability_id], vuln[:package_uid], vuln[:target_file]] }.to_set
  head_set = head_vulnerabilities.map { |vuln| [vuln[:vulnerability_id], vuln[:package_uid], vuln[:target_file]] }.to_set
  # Find vulnerabilities in the head that are not in the base (i.e., newly introduced)
  new_vulnerabilities = head_set - base_set
  # Map back to original vuln details for the new vulnerabilities
  new_vulnerabilities_details = new_vulnerabilities.map do |vuln|
    head_vulnerabilities.find { |h| h[:vulnerability_id] == vuln[0] && h[:package_uid] == vuln[1] && h[:target_file] == vuln[2] }
  end
  new_vulnerabilities_details
end
# Helper function to colorize text based on severity
def colorize_severity(severity)
  case severity
  when 'CRITICAL'
    COLOR_RED
  when 'HIGH'
    COLOR_YELLOW
  when 'LOW'
    COLOR_GREEN
  else
    RESET_TEXT_FORMATTING
  end
end
# Output new vulnerabilities with color
def output_new_vulnerabilities(new_vulnerabilities)
  if new_vulnerabilities.empty?
    puts "#{COLOR_GREEN}No new vulnerabilities introduced.#{RESET_TEXT_FORMATTING}"
  else
    puts "#{COLOR_RED}New vulnerabilities introduced:#{RESET_TEXT_FORMATTING}"
    new_vulnerabilities.each do |vuln|
      puts "#{RESET_TEXT_FORMATTING}----------------------------------------"
      puts "Vulnerability ID: #{COLOR_RED}#{vuln[:vulnerability_id]} #{RESET_TEXT_FORMATTING}(Severity: #{colorize_severity(vuln[:severity])}#{vuln[:severity]}#{RESET_TEXT_FORMATTING})"
      puts "  File: #{vuln[:target_file]}"
      puts "  Package: #{vuln[:pkg_name]} (Installed Version: #{vuln[:installed_version]})"
      puts "  Fixed Version: #{COLOR_GREEN}#{vuln[:fixed_version]}#{RESET_TEXT_FORMATTING}"
      puts "  CVSS Score: #{vuln[:cvss_score]}"
      puts "  Published Date: #{vuln[:published_date]}"
      puts "  Description: #{vuln[:description]}"
      
      if vuln[:references].any?
        puts "  References:"
        vuln[:references].take(5).each do |ref|
          puts "    - #{ref}"
        end
      end
      puts "#{RESET_TEXT_FORMATTING}----------------------------------------"
    end
        
    puts "#{COLOR_YELLOW} Failed due to the introduction of new vulnerabilities. Please review the details above and address them before proceeding with the merge.#{RESET_TEXT_FORMATTING}"
    exit(1)
  end
end
# Main comparison logic
def run_comparison(base_file, head_file)
  # Load and parse JSON files
  base_vulnerabilities = load_vulnerabilities(base_file)
  head_vulnerabilities = load_vulnerabilities(head_file)
  base_parsed = parse_vulnerabilities(base_vulnerabilities)
  head_parsed = parse_vulnerabilities(head_vulnerabilities)
  # Compare vulnerabilities and identify new ones
  new_vulnerabilities = compare_vulnerabilities(base_parsed, head_parsed)
  # Output results
  output_new_vulnerabilities(new_vulnerabilities)
end
# Run the comparison with the paths to the base and head commit JSON files
base_file = 'base_vulnerabilities.json'
head_file = 'head_vulnerabilities.json'
run_comparison(base_file, head_file)
