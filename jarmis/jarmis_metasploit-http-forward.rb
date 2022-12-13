##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP Redirect',
      'Description'    => %q{
        Setup an HTTP Server and redirect
      },
      'Author'      => ['Me'],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Redirect', 'Description' => 'Run redirect web server' ]
        ],
      'PassiveActions' =>
        [
          'Redirect'
        ],
      'DefaultAction'  => 'Redirect'
    ))

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 80 ]),
        OptString.new('RedirectURL', [ false, "The page to redirect users to after they enter basic auth creds" ]),
        OptBool.new('SSL', [ true, "Negotiate SSL", true])
      ])
  end

  # Not compatible today
  def support_ipv6?
    false
  end

  def run
    @myhost   = datastore['SRVHOST']
    @myport   = datastore['SRVPORT']

    exploit
  end

  def on_request_uri(cli, req)
      print_status("Redirecting client #{cli.peerhost} to #{datastore['RedirectURL']}")
      send_redirect(cli, datastore['RedirectURL'])
  end
end
