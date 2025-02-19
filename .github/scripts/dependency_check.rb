require 'set'
require 'json'
require 'time'

# Color codes for output
COLORS = {
  'CRITICAL' => "\033[38;5;160m",
  'HIGH'     => "\033[38;5;203m",
  'MEDIUM'   => "\033[38;5;214m",
  'LOW'      => "\033[38;5;226m",
  'UNKNOWN'  => "\033[38;5;4m",
  'GREEN'    => "\033[38;5;48m",
  'RESET'    => "\033[0m"
}

# Load JSON file
def load_vulnerabilities(file)
  JSON.parse(File.read(file))
end

# Extract relevant vulnerability data
def parse_vulnerabilities(vulnerabilities_json)
  vulnerabilities_json['Results'].flat_map do |result|
    next unless result['Vulnerabilities']
    
    result['Vulnerabilities'].map do |vuln|
      {
        # Required fields:
        vulnerability_id: vuln['VulnerabilityID'],
        pkg_id:           vuln['PkgID'],
        target_file:      result['Target'],
        severity:         vuln['Severity'],
        title:            vuln['Title'],
        fixed_version:    vuln['FixedVersion'],
        pkg_name:         vuln['PkgName'],
        installed_version: vuln['InstalledVersion'],
        published_date:   vuln['PublishedDate'] || nil,
        description:      vuln['Description'],
        references:       vuln['References'] || []
      }
    end
  end.compact
end

# Identify newly introduced vulnerabilities
def compare_vulnerabilities(base_vulnerabilities, head_vulnerabilities)
  base_set = base_vulnerabilities.map { |v| [v[:vulnerability_id], v[:pkg_id], v[:target_file]] }.to_set
  head_vulnerabilities.select { |v| !base_set.include?([v[:vulnerability_id], v[:pkg_id], v[:target_file]]) }
end

# Output new vulnerabilities with color formatting
def output_new_vulnerabilities(new_vulnerabilities)
  if new_vulnerabilities.empty?
    puts "#{COLORS['GREEN']}No new vulnerabilities introduced.#{COLORS['RESET']}"
    return
  end

  puts "#{COLORS['HIGH']}New vulnerabilities introduced:#{COLORS['RESET']}\n\n"

  new_vulnerabilities.each do |vuln|
    severity_color = COLORS[vuln[:severity]] || COLORS['RESET']
    formatted_date = vuln[:published_date] ? Time.parse(vuln[:published_date]).strftime("%B %d, %Y") : "N/A"

    puts <<~VULN
      📌 Vulnerability ID: #{COLORS['HIGH']}#{vuln[:vulnerability_id]}#{COLORS['RESET']} (Severity: #{severity_color}#{vuln[:severity] || "N/A"}#{COLORS['RESET']})
        File: #{vuln[:target_file]}
        Package: #{vuln[:pkg_name] || "N/A"} (Installed Version: #{vuln[:installed_version] || "N/A"})
        Fixed Version: #{vuln[:fixed_version] || "N/A"}
        Published Date: #{formatted_date}
        Description: #{vuln[:description] || "N/A"}
    VULN

    if vuln[:references]&.any?
      puts "  References:"
      vuln[:references].take(5).each { |ref| puts "    - #{ref}" }
    end
    puts "#{'=' * 55}"
  end

  puts "#{COLORS['MEDIUM']}Failed due to the introduction of new vulnerabilities. Please review the details above.#{COLORS['RESET']}"
  exit(1)
end

# Main execution
def run_comparison(base_file, head_file)
  base_parsed = parse_vulnerabilities(load_vulnerabilities(base_file))
  head_parsed = parse_vulnerabilities(load_vulnerabilities(head_file))

  new_vulnerabilities = compare_vulnerabilities(base_parsed, head_parsed)
  output_new_vulnerabilities(new_vulnerabilities)
end

# Execute with predefined JSON file paths
run_comparison('base_vulnerabilities.json', 'head_vulnerabilities.json')
