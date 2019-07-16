var Login = Login || {};

Login.LoginSistemas = (function() {
	
	function sha1 (msg) {
		function rotate_left(n,s) {
			var t4 = ( n<<s ) | (n>>>(32-s));
			return t4;
		};
		function lsb_hex(val) {
			var str="";
			var i;
			var vh;
			var vl;
			for( i=0; i<=6; i+=2 ) {
				vh = (val>>>(i*4+4))&0x0f;
				vl = (val>>>(i*4))&0x0f;
				str += vh.toString(16) + vl.toString(16);
			}
			return str;
		};
		function cvt_hex(val) {
			var str="";
			var i;
			var v;
			for( i=7; i>=0; i-- ) {
				v = (val>>>(i*4))&0x0f;
				str += v.toString(16);
			}
			return str;
		};
		function Utf8Encode(string) {
			string = string.replace(/\r\n/g,"\n");
			var utftext = "";
			for (var n = 0; n < string.length; n++) {
				var c = string.charCodeAt(n);
				if (c < 128) {
					utftext += String.fromCharCode(c);
				}
				else if((c > 127) && (c < 2048)) {
					utftext += String.fromCharCode((c >> 6) | 192);
					utftext += String.fromCharCode((c & 63) | 128);
				}
				else {
					utftext += String.fromCharCode((c >> 12) | 224);
					utftext += String.fromCharCode(((c >> 6) & 63) | 128);
					utftext += String.fromCharCode((c & 63) | 128);
				}
			}
			return utftext;
		};
		function hex2bin(hex)
		{
			var bytes = [], str;

			for(var i=0; i< hex.length-1; i+=2)
				bytes.push(parseInt(hex.substr(i, 2), 16));

			return String.fromCharCode.apply(String, bytes);    
		};
		var blockstart;
		var i, j;
		var W = new Array(80);
		var H0 = 0x67452301;
		var H1 = 0xEFCDAB89;
		var H2 = 0x98BADCFE;
		var H3 = 0x10325476;
		var H4 = 0xC3D2E1F0;
		var A, B, C, D, E;
		var temp;
		msg = Utf8Encode(msg);
		var msg_len = msg.length;
		var word_array = new Array();
		for( i=0; i<msg_len-3; i+=4 ) {
			j = msg.charCodeAt(i)<<24 | msg.charCodeAt(i+1)<<16 |
			msg.charCodeAt(i+2)<<8 | msg.charCodeAt(i+3);
			word_array.push( j );
		}
		switch( msg_len % 4 ) {
			case 0:
				i = 0x080000000;
			break;
			case 1:
				i = msg.charCodeAt(msg_len-1)<<24 | 0x0800000;
			break;
			case 2:
				i = msg.charCodeAt(msg_len-2)<<24 | msg.charCodeAt(msg_len-1)<<16 | 0x08000;
			break;
			case 3:
				i = msg.charCodeAt(msg_len-3)<<24 | msg.charCodeAt(msg_len-2)<<16 | msg.charCodeAt(msg_len-1)<<8    | 0x80;
			break;
		}
		word_array.push( i );
		while( (word_array.length % 16) != 14 ) word_array.push( 0 );
		word_array.push( msg_len>>>29 );
		word_array.push( (msg_len<<3)&0x0ffffffff );
		for ( blockstart=0; blockstart<word_array.length; blockstart+=16 ) {
			for( i=0; i<16; i++ ) W[i] = word_array[blockstart+i];
			for( i=16; i<=79; i++ ) W[i] = rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
			A = H0;
			B = H1;
			C = H2;
			D = H3;
			E = H4;
			for( i= 0; i<=19; i++ ) {
				temp = (rotate_left(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			for( i=20; i<=39; i++ ) {
				temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			for( i=40; i<=59; i++ ) {
				temp = (rotate_left(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			for( i=60; i<=79; i++ ) {
				temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			H0 = (H0 + A) & 0x0ffffffff;
			H1 = (H1 + B) & 0x0ffffffff;
			H2 = (H2 + C) & 0x0ffffffff;
			H3 = (H3 + D) & 0x0ffffffff;
			H4 = (H4 + E) & 0x0ffffffff;
		}
		var temp = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
		return window.btoa(hex2bin(temp.toUpperCase()));
	}
	
	function LoginSistemas() {
		this.form = $('#sign_in');
		this.botaoLogin = $('#enter');
		this.username = $('#username');
		this.pass = $('#pass');
		this.error = $("#error");
	}
	
	LoginSistemas.prototype.iniciar = function() {
		this.botaoLogin.on('click', onSubmitLogin.bind(this));
		this.form.on('submit', onSubmitLogin.bind(this));
		this.username.on('focus', onRemoveDiv.bind(this));
		this.pass.on('focus', onRemoveDiv.bind(this));
	}
	
	function onSubmitLogin(e) {
		if($('#username').val() == "" || $('#pass').val() == ""){
			onRemoveDiv();
			this.error.append('<div id="validate" class="alert alert-danger" role="alert">O login e a senha devem ser preenchidos.</div>');
			return;
		}

		e.preventDefault();
		var urlBase = '';
		var protocol = window.location.protocol;
		var baseUrl = protocol + '//' + window.location.hostname;
		// Pode ser que esteja atras de um proxy e não vai ter porta na url
		if (window.location.port != ""){
			baseUrl = baseUrl + ':' + window.location.port; 
		}
		var querystring = getQuerystring();
		var url = baseUrl + '/dados/code_request?'+
				 'client_id=' + querystring['client_id']+
				 '&state=' + querystring['state']+
				 '&redirect_uri=' + querystring['redirect_uri'];
		$.ajax({
			url: url,
			crossDomain: true,
			contentType: 'application/json',
			beforeSend: function (xhr) {
				xhr.setRequestHeader ("Authorization", "Basic " + btoa($('#username').val().trim() + ":" + $('#pass').val()));
			},
			error: onErroSalvandoEstilo.bind(this),
			success: function(data, textStatus, headers){
				if (data.redirect) {
					window.location.href = data.redirect;
				}
			},
			complete: function(data, textStatus) {
				if(textStatus == 'success'){
					var referrer = document.referrer;
					if (referrer != undefined && referrer != ""){
						baseUrlReferrer = referrer.split('/');
						url = baseUrlReferrer[0] + '//' + baseUrlReferrer[2] + data.getResponseHeader("Location");
					}else{
						if (baseUrl.startsWith("/")){
							url = baseUrl + data.getResponseHeader("Location");
						}else{
							url = data.getResponseHeader("Location")
						}
					}
					window.location.href = url;
				}
			}
		});
	}
	
	//erro na autenticação
	function onErroSalvandoEstilo(obj) {
		onRemoveDiv();
		this.error.append('<div id="validate" class="alert alert-danger" role="alert">Usuário ou senha inválido(s).</div>');
	}
	
	//sucesso na autenticado
	function onEstiloSalvo(estilo) {
		this.error.append('<div class="alert alert-danger" role="alert">Ok.</div>');
	}
	
	function onRemoveDiv() {
		var divElement = $("#validate");
		if(divElement != undefined){
			divElement.remove("#validate");		
		}
	}
	
	function getQuerystring(){
		var vars = [], param;
		var href = window.location.href;
		var posQuerystring = href.indexOf('?');
		if (posQuerystring > 0){
			var hashes = href.slice(posQuerystring + 1).split('&');
			for(var i = 0; i < hashes.length; i++)
			{
				param = hashes[i].split('=');
				paramName = param[0];
				vars.push(paramName);
				vars[paramName] = param[1];
			}
		}
		return vars;
	}
	
	return LoginSistemas;
	
}());

$(function() {
	var loginSistemas = new Login.LoginSistemas();
	loginSistemas.iniciar();
});
