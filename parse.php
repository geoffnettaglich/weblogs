<?php 

$opts = getopt("f:s::r");
foreach (array_keys($opts) as $opt) switch ($opt) {
  case 's':
    // Do something with s parameter
    $server_override = $opts['s'];
    break;
  case 'r':
    $syslog = true;
    break;
  case 'f':
    $file = $opts['f'];
    break;
}

global $max;
$max = 0;

$file_handle = fopen($file, "r");

if(!$file_handle)
{
  die("Failed to open file");
}

$con = null;

try 
{
  $con = connect_db('web_logs', '127.0.0.1', 'web', 'w3bu53r');
  $con->beginTransaction();
  $stmt = prepare_statement($con);
  $count = 0;
  
  while (!feof($file_handle)) 
  {
    $line = fgets($file_handle);
  
    if($syslog)
    {
      list($prefix, $line) = explode('\d+\:', $line);
      
      if($server_override)
      {
        $server = $server_override;
      }
      else
      {
        // lets try and derive 'server' from the syslog line
        $data = preg_split('/\s+/', $prefix);
        list($mon, $day, $time, $server) = $data; 
      }
    }
    
    if($line) 
    {
      $line = trim($line);
      $data = process_line($line, $server);

      #print_r($data);

      if($data)
      {
        insert_data($data, $stmt);
        $count++;
      }
      else
      {
        print "PROBLEM :: $line\n";
        print_r($data);
      }
    }
  }
  
  $con->commit();
}
catch(PDOException $e)
{
  print($e->getMessage());
  if($con)
  {
    $con->rollback();
  }
}

fclose($file_handle);

print("Max uri length: $max\nInserted lines: $count\n");

function process_line($line, $server)
{
  $data = array();
  $pattern = '/^([^\[]+\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "([^\"]+)" (\S+) (\S+) "([^"]*)" "([^"]+)"\s*(.*)/';

  $results = NULL;

  if(preg_match($pattern, $line, $data))
  {

  list($line, $preamble, $date, $time,
       $time_zone, $req,
       $status, $bytes,
       $referer, $agent, $other) = $data;

  $req_arr = preg_split('/\s+/', $req);

  $method = array_shift($req_arr);
  $url = array_shift($req_arr);
  $protocol = array_shift($req_arr);
  // NOTE: $preamble variable contains client IP (or comma separated list of IPs) 
  // as well as remote user and uath user - WE IGNORE THIS FOR NOW
  
  list($uri, $params) = preg_split('/\?/', $url);
  
  $sections = array_slice(explode('/', $uri), 0, 2);
  $section = join('/', $sections);

  global $max;
  
  $len = strlen($params);
  if($len > $max)
  {
    $max = $len;
  }

  $format = '%d/%h/%Y %H:%M:%S';
  $date_stamp = strptime("$date $time", $format);

  $year  = $date_stamp['tm_year'] + 1900;
  $month = $date_stamp['tm_mon'] + 1;
  $day   = $date_stamp['tm_mday'];
  $hour  = $date_stamp['tm_hour'];
  $min   = $date_stamp['tm_min'];
  $sec   = $date_stamp['tm_sec'];
   
  $agent_type = guess_agent_type($agent, $preamble);
  $request_type = guess_request_type($url);
     
  if($other)
  {
    list($host, $firstByte) = preg_split('/\s+/', $other);
    $host = preg_replace('/"/', '', $host);
  }
  else
  {
    $host = '-';
    $firstByte = NULL;
  }
   
  $results = array(
      'server' => $server,
      'host'   => $host,
      'year'   => $year,
      'month'  => $month,
      'day'    => $day, 
      'hour'   => $hour,
      'min'    => $min,
      'sec'    => $sec,
      'section' => $section,
      #'params' => $params,
      'agent'  => $agent,
      'bytes'  => $bytes,
      'status' => $status,
      'agent_type' => $agent_type,
      'request_type' => $request_type,
      'referer' => $referer,
      'uri'    => $uri,
      'first_byte' =>$firstByte);
  }

  return $results;
}

function guess_request_type($url) 
{
  $types = array(
    'image'  => '/\.(jpg|png|gif)/',
    'script' => '/\.(js)/',
    'css'    => '/\.(css)/',
    'asset'  => '/\.(pdf|html)/i'
  );
  
  foreach($types as $type => $pattern)
  {
    if(preg_match($pattern, $url))
    {
      return $type;
    }
  }
  
  return 'dynamic';
}

function guess_agent_type($agent, $client)
{
  if(preg_match('/googlebot/i', $agent) ||
     preg_match('/baiduspider/i', $agent) || 
     preg_match('/yandexbot/i', $agent) || 
     preg_match('/yahoo\! slurp/i', $agent) || 
     preg_match('/ezooms/i', $agent) || 
     preg_match('/ahrefsbot/i', $agent) || 
     preg_match('/bingbot/i', $agent) || 
     preg_match('/msnbot/i', $agent))
  {
    $type = 'bot';
  }
  else if(preg_match('/pingdom/i', $agent))
  {
    $type = "pingdom";
  }
  else if(preg_match('/internal dummy connection/i', $agent))
  {
    $type = 'internal';
  }
  else if(preg_match('/http-monitor/i', $agent) || preg_match('/^65\.17\.251\.19/', $client))
  {
    $type = 'load-balancer';
  }
  else if(preg_match('/safari/i', $agent))
  {
    $type = 'safari';
  }
  else if(preg_match('/chrome/i', $agent))
  {
    $type = 'chrome';
  }
  else if(preg_match('/opera/i', $agent))
  {
    $type = 'firefox';
  }
  else if(preg_match('/firefox/i', $agent))
  {
    $type = 'firefox';
  }
  else if(preg_match('/msie/i', $agent))
  {
    $type = 'IE';
  }
  else
  {
    $type = 'unknown';
  }
  
  return $type;
}

function connect_db($db, $server, $username, $password)
{
  $con = new PDO("mysql:host=$server;dbname=$db", $username, $password);
  return $con;
}

function insert_data($data, $statement) 
{
  $params = array();
  
  foreach($data as $col => $val)
  {
    $params[':'.$col] = $val;
  }

  if(!$statement->execute($params))
  {
    print_r($statement->errorInfo());
    $statement->debugDumpParams();
  }
}

function prepare_statement($con)
{
$stmt = $con->prepare("INSERT INTO pulse_logs 
(
  server,
  host,
  year,
  month,
  day, 
  hour,
  min,
  sec,
  section,
  agent,
  agent_type,
  request_type,
  first_byte,
  bytes,
  status,
  referer,
  uri
)
VALUES 
(
  :server,
  :host,
  :year,
  :month,
  :day, 
  :hour,
  :min,
  :sec,
  :section,
  :agent,
  :agent_type,
  :request_type,
  :first_byte,
  :bytes,
  :status,
  :referer,
  :uri
)");

  return $stmt;
}
