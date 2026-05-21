package payload

import _ "embed"

//go:embed tunnel.php
var PHPTemplate string

//go:embed tunnel.jsp
var JSPTemplate string
