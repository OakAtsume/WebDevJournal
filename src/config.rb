# frozen_string_literal: true

require('json')
require('digest')
$Settings = {
  'Port' => 8080,
  'SSL-Key' => 'src/server.key',
  'SSL-Cert' => 'src/server.crt',
  'Verify-SSL' => false,
  'FireLock' => 'src/firelock.json',
  'AutoBlock' => true,
  'MaxRead' => 2048,
  'RawFilesExts' => %w[
    ico
    jpg
    jpeg
    png
    gif
    svg
    css
    js
    txt
    webp
  ]
}

$Paths = {
  'root' => 'Index', # Root directory for the web server
  'robots' => 'robots.txt', # Path to the robots.txt file
  'favicon' => 'Index/favicon.ico' # Path to the favicon.ico file
}
$Errors = {
  '404' => 'Index/error/404.html', # Path to the 404 error Index
  '500' => 'Index/error/500.html', # Path to the 500 error Index
  '503' => 'Index/error/503.html', # Path to the 503 error Index
  'Blocked' => 'Index/error/firelock.html' # Path to the blocked Index
}

class Decoder
  def initialize
    puts('Decoder initialized')
  end

  def generateNewToken
    # Generate a new token
    random = Random.new
    output = ''
    32.times do
      output += random.rand(0..9).to_s
    end
    output
  end

  def sha256(input)
    # Generate a SHA256 hash

    Digest::SHA256.hexdigest(input)
  end

  def decode(request)
    # map request to an array
    output = {}
    # split the request in to array sections by \r\n
    data = request.split("\r\n")
    output['method'] = data[0].split(' ')[0]
    output['path'] = data[0].split(' ')[1]
    output['version'] = data[0].split(' ')[2]
    # Continue and split any [key]: [value] pairs
    data.each do |line|
      output[line.split(': ')[0]] = line.split(': ')[1] if line.include?(':')
    end
    output['data'] = data[data.length - 1]
    output
  end

  def parseData(data)
    # Split key=value pairs by &
    output = {}
    data.split('&').each do |pair|
      output[pair.split('=')[0]] = pair.split('=')[1]
    end
    output
  end

  def parseCookies(cookies)
    # Split key=value pairs by ;
    output = {}
    cookies.split('; ').each do |pair|
      output[pair.split('=')[0]] = pair.split('=')[1]
    end
    output
  end

  def extractIp(request)
    # Check request for any X-Forwarded-For headers
    return request['X-Forwarded-For'] unless request['X-Forwarded-For'].nil?

    return request['Remote-Addr']

    # Check request for any X-Real-IP headers
    return request['X-Real-IP'] unless request['X-Real-IP'].nil?

    request['Remote-Addr']
  end
end

class SControl
  def initialize
    @fireLock = JSON.parse(File.read($Settings['FireLock']))
  end

  def getProducts
    File.read('db/products.json')
  end

  def getUserDB
    File.read('db/users.json')
  end

  def writeUserDB(data)
    File.write('db/users.json', data)
  end

  def refreshFireLock
    @fireLock = JSON.parse(File.read($Settings['FireLock']))
  end

  def isIpBlocked(ip)
    return true if @fireLock['BlockedIP'].include?(ip)

    false
  end

  def isUaBlocked(ua)
    return true if @fireLock['BlockedUA'].include?(ua)

    false
  end

  def isPathBlocked(path)
    return true if @fireLock['IlegalPaths'].include?(path)

    false
  end

  def blockIp(ip)
    return if @fireLock['BlockedIP'].include?(ip)

    @fireLock['BlockedIP'].push(ip)
    File.write($Settings['FireLock'], JSON.pretty_generate(@fireLock))
    refreshFireLock
  end
end
