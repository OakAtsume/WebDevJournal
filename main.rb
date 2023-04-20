require("socket")
require("json")
require("openssl")
require_relative("src/config")

Control = SControl.new
Codec = Decoder.new

tcpHandler = TCPServer.new($Settings["Port"])
sslC = OpenSSL::SSL::SSLContext.new
sslC.cert = OpenSSL::X509::Certificate.new(File.read($Settings["SSL-Cert"]))
sslC.key = OpenSSL::PKey::RSA.new(File.read($Settings["SSL-Key"]))
sslC.verify_mode = OpenSSL::SSL::VERIFY_NONE
# User SSLv2
sslC.ssl_version = :SSLv3
# # Set TLS version to 1.1
sslC.ssl_version = :TLSv1_2
# Disable report_on_exception
sslC.options = OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS

sslHandler = OpenSSL::SSL::SSLServer.new(tcpHandler, sslC)
puts("Server started on port #{$Settings["Port"]}")

loop do
  Thread.start(sslHandler.accept) do |client|
    begin
      request = Codec.decode(client.readpartial(1024))
    rescue StandardError
      puts("Reading-error: #{$ERROR_INFO}")
    end
    next if request.nil?

    # If request's IP is 0.0.0.0 or 127.0.0.1 then we can assume it's a tunnel
    if client.peeraddr[3] == "0.0.0.0" || client.peeraddr[3] == "127.0.0.1"
      clientIp = Codec.extractIp(request)
      # if clientIp == nil
      clientIp = client.peeraddr[3] if clientIp.nil?
    else
      clientIp = client.peeraddr[3]
    end

    # Firelock-Pahe #
    if Control.isIpBlocked(clientIp) || Control.isUaBlocked(request["User-Agent"]) || Control.isPathBlocked(request["path"]) || request["path"].include?("..")
      puts("[Firelock] blocked #{clientIp} : #{request["path"]} : #{request["User-Agent"]}")
      data = File.read($Errors["Blocked"])
      # Split , and add <br> to each line
      data = data.gsub(%r{</body>},
                       "<p>You have been blocked from accessing this site.</p></br><code>#{JSON.pretty_generate(request)}</code></body>")
      client.print("HTTP/1.1 403 Forbidden\r\n")
      client.print("Content-Type: text/html\r\n")
      client.print("Content-Length: #{data.length}\r\n")
      client.print("Connection: close\r\n\r\n")
      client.print(data)
      client.close
      next
      # Check if user is IP blocked
      unless Control.isIpBlocked(clientIp)
        puts("[Firelock-Block] #{clientIp} : #{request["path"]} : #{request["User-Agent"]}")
        Control.blockIp(clientIp)
      end
      next
    end
    request["path"] = request["path"].gsub(%r{/+}, "/") if request["path"].include?("//")
    request["path"] = "index.html" if request["path"] == "/"
    path = "#{$Paths["root"]}/#{request["path"]}"
    if File.exist?(path) && File.file?(path)
      if request["path"].include?(".")
        ext = request["path"].split(".")[1]
        if $Settings["RawFilesExts"].include?(ext)
          puts("[File]: #{clientIp}, #{request["path"]}")
          data = File.read(path)
          client.print("HTTP/1.1 200 OK\r\n")
          client.print("Content-Type: #{ext}\r\n")
          client.print("Connection: close\r\n\r\n")
          client.print(data)
          client.close
          next
        end
      end
    else
      puts("[404]: #{clientIp}, #{request["path"]} : #{request["User-Agent"]}")
      data = File.read($Errors["404"])
      client.print("HTTP/1.1 404 Not Found\r\n")
      client.print("Content-Type: text/html\r\n")
      client.print("Content-Length: #{data.length}\r\n")
      client.print("Connection: close\r\n\r\n")
      client.print(data)
      client.close
      next
    end
    puts("[Page]: #{clientIp}, #{request["path"]}")
    data = File.read(path)
    client.print("HTTP/1.1 200 OK\r\n")
    client.print("Content-Type: #{ext}\r\n")
    client.print("Content-Length: #{data.length}\r\n")
    client.print("Connection: close\r\n\r\n")
    client.print(data)
    client.close
    next
  end
rescue StandardError => e
  puts("[Catch] #{e} : #{e.backtrace}")
end
