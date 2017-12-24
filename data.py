


web_start ="""
<head>
  <title>AFL manager</title>
  <meta http-equiv="refresh" content="5" >
  <link rel="stylesheet" type="text/css" href="source.css">

</head>
<body>
<h1><span class="blue">&lt;</span>AFL<span class="blue">&gt;</span> <span class="yellow">MANAGER</pan></h1>
<h2></h2>
<th><h1><a href='crashes'>ALL CRASH</a></h1></th>

<table class="container">
  <thead>
    <tr>
      <th><h1>Name</h1></th>
      <th><h1>Run time</h1></th>
      <th><h1>Speed</h1></th>
      <th><h1>Crash</h1></th>
      <th><h1>Last crash</h1></th>
      <th><h1>Cov</h1></th>
      <th><h1>Status</h1></th>
      <th><h1>View</h1></th>
    </tr>
  </thead>
  <tbody>
"""

web_end = """</tbody>
</table>
</span>
</h1>
</body>
"""

crash_start = """
<head>
  <title>AFL manager</title>
  <meta http-equiv="refresh" content="5" >
  <link rel="stylesheet" type="text/css" href="source.css">
</head>
<body>
<h1><span class="blue">&lt;</span>AFL<span class="blue">&gt;</span> <span class="yellow">MANAGER</pan></h1>
<h2></h2>
<table class="container">
  <thead>
    <tr>
      <th><h1>Created Time</h1></th>
      <th><h1>Name</h1></th>
      <th><h1>Info</h1></th>
    </tr>
  </thead>
  <tbody>
"""

finfo_start = """
<table class="container">
  <thead>
    <tr>
      <th><h1>Filename</h1></th>
      <th><h1>Data</h1></th>
    </tr>
  </thead>
  <tbody>
"""

finfo_end = """
</tbody>
</table>
</span>
</h1>
</body>"""



all_crash_start= """
<head>
  <title>AFL manager</title>
  <meta http-equiv="refresh" content="5" >
  <link rel="stylesheet" type="text/css" href="source.css">

</head>
<body>
<h1><span class="blue">&lt;</span>AFL<span class="blue">&gt;</span> <span class="yellow">MANAGER</pan></h1>
<h2></h2>
<table class="container">
  <thead>
    <tr>
      <th><h1>Client Name</h1></th>
      <th><h1>Created Time</h1></th>
      <th><h1>File Name</h1></th>
      <th><h1>Info</h1></th>
    </tr>
  </thead>
  <tbody>
"""

