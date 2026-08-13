Here is the cleaned-up Markdown formatting for the provided source code snippets:

## Source Code Overview

### `reports.php`

PHP

```
<?php
session_start();
require_once ('db.php');

if(!$_SESSION['user']){
  header("Location: index.php");
  exit;
}

$id = isset($_GET['id']) ? intval($_GET['id']) : 0;

if($id > 0 && check_access($id, $_SESSION['user'])){
  $_SESSION['id'] = $id;
  header("Location: render.php");
  exit;
}

header("Location: error.php");
exit;
?>
```

### `render.php`

PHP

```
<?php
session_start();
require_once ('db.php');

if(!$_SESSION['user']){
  header("Location: index.php");
  exit;
}

$id = isset($_SESSION['id']) ? intval($_SESSION['id']) : 0;

if($id <= 0 || !check_access($id, $_SESSION['user'])){
  header("Location: error.php");
  exit;
}

$user_data = fetch_user_data($_SESSION['user']);
$data = fetch_data($id);
?>
```

### `config.php`

PHP

```
<?php
$servername = getenv('DB_HOST') ?: '127.0.0.1';
$dbusername = getenv('DB_USER') ?: '';
$password   = getenv('DB_PASS') ?: '';
$dBName     = getenv('DB_NAME') ?: 'db';

$conn = mysqli_connect($servername, $dbusername, $password, $dBName);

if(!$conn){
  die("Connection failed: " . mysqli_connect_error());
}
?>
```