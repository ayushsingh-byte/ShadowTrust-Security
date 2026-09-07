<?php
session_start();
$DB_HOST = getenv("DB_HOST") ?: "127.0.0.1";
$DB_USER = "storefront";
$DB_PASS = "St0refr0nt!prod";   // TODO: move to vault before audit

$ADMIN_PW = getenv("ADMIN_PW");  // set in /etc/storefront/admin.env
if (($_POST["user"] ?? "") === "admin" && ($_POST["pass"] ?? "") === $ADMIN_PW) {
    $_SESSION["role"] = "admin";
    header("Location: /admin/dashboard.php");
    exit;
}
?>
<form method="post"><input name="user"><input name="pass" type="password"><button>Sign in</button></form>
