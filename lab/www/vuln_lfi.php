<?php
// Simulates a common LFI vulnerability (e.g. page= parameter)
// This is the second half of the attack chain
$page = $_GET['page'] ?? 'index.php';
include($page);
