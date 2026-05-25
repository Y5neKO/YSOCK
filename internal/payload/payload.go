package payload

import _ "embed"

//go:embed tunnel.php
var PHPTemplate string

//go:embed tunnel.jsp
var JSPTemplate string

//go:embed tunnel.jspx
var JSPXTemplate string

//go:embed tunnel.aspx
var ASPXTemplate string

//go:embed tunnel.asp
var ASPTemplate string

//go:embed handler.java
var JavaTemplate string

//go:embed handler.cs
var CSTemplate string
