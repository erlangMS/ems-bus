import $ from 'jquery';

class Login {

    constructor() {
        this.form = $('#sign_in');
        this.botaoLogin = $('#enter');
        this.username = $('#username');
        this.pass = $('#pass');
        this.error = $("#error");
        this.botaoLogin.on('click', this.onEnter.bind(this));
        this.username.on('focus', this.onRemoveDiv.bind(this));
        this.pass.on('focus', this.onRemoveDiv.bind(this));
    }

    sha1(msg) {
        function rotate_left(n, s) {
            let t4 = (n << s) | (n >>> (32 - s));
            return t4;
        };

        function lsb_hex(val) {
            let str = "";
            let i;
            let vh;
            let vl;
            for (i = 0; i <= 6; i += 2) {
                vh = (val >>> (i * 4 + 4)) & 0x0f;
                vl = (val >>> (i * 4)) & 0x0f;
                str += vh.toString(16) + vl.toString(16);
            }
            return str;
        };

        function cvt_hex(val) {
            let str = "";
            let i;
            let v;
            for (i = 7; i >= 0; i--) {
                v = (val >>> (i * 4)) & 0x0f;
                str += v.toString(16);
            }
            return str;
        };

        function Utf8Encode(string) {
            string = string.replace(/\r\n/g, "\n");
            let utftext = "";
            for (let n = 0; n < string.length; n++) {
                let c = string.charCodeAt(n);
                if (c < 128) {
                    utftext += String.fromCharCode(c);
                } else if ((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                } else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
            }
            return utftext;
        };

        function hex2bin(hex) {
            let bytes = [],
                str;

            for (let i = 0; i < hex.length - 1; i += 2)
                bytes.push(parseInt(hex.substr(i, 2), 16));

            return String.fromCharCode.apply(String, bytes);
        };
        let blockstart;
        let i, j;
        let W = new Array(80);
        let H0 = 0x67452301;
        let H1 = 0xEFCDAB89;
        let H2 = 0x98BADCFE;
        let H3 = 0x10325476;
        let H4 = 0xC3D2E1F0;
        let A, B, C, D, E;
        let temp;
        msg = Utf8Encode(msg);
        let msg_len = msg.length;
        let word_array = new Array();
        for (i = 0; i < msg_len - 3; i += 4) {
            j = msg.charCodeAt(i) << 24 | msg.charCodeAt(i + 1) << 16 |
                msg.charCodeAt(i + 2) << 8 | msg.charCodeAt(i + 3);
            word_array.push(j);
        }
        switch (msg_len % 4) {
            case 0:
                i = 0x080000000;
                break;
            case 1:
                i = msg.charCodeAt(msg_len - 1) << 24 | 0x0800000;
                break;
            case 2:
                i = msg.charCodeAt(msg_len - 2) << 24 | msg.charCodeAt(msg_len - 1) << 16 | 0x08000;
                break;
            case 3:
                i = msg.charCodeAt(msg_len - 3) << 24 | msg.charCodeAt(msg_len - 2) << 16 | msg.charCodeAt(msg_len - 1) << 8 | 0x80;
                break;
        }
        word_array.push(i);
        while ((word_array.length % 16) != 14) word_array.push(0);
        word_array.push(msg_len >>> 29);
        word_array.push((msg_len << 3) & 0x0ffffffff);
        for (blockstart = 0; blockstart < word_array.length; blockstart += 16) {
            for (i = 0; i < 16; i++) W[i] = word_array[blockstart + i];
            for (i = 16; i <= 79; i++) W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
            A = H0;
            B = H1;
            C = H2;
            D = H3;
            E = H4;
            for (i = 0; i <= 19; i++) {
                temp = (rotate_left(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
                E = D;
                D = C;
                C = rotate_left(B, 30);
                B = A;
                A = temp;
            }
            for (i = 20; i <= 39; i++) {
                temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
                E = D;
                D = C;
                C = rotate_left(B, 30);
                B = A;
                A = temp;
            }
            for (i = 40; i <= 59; i++) {
                temp = (rotate_left(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
                E = D;
                D = C;
                C = rotate_left(B, 30);
                B = A;
                A = temp;
            }
            for (i = 60; i <= 79; i++) {
                temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
                E = D;
                D = C;
                C = rotate_left(B, 30);
                B = A;
                A = temp;
            }
            H0 = (H0 + A) & 0x0ffffffff;
            H1 = (H1 + B) & 0x0ffffffff;
            H2 = (H2 + C) & 0x0ffffffff;
            H3 = (H3 + D) & 0x0ffffffff;
            H4 = (H4 + E) & 0x0ffffffff;
        }
        const result = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
        return window.btoa(hex2bin(temp.toUpperCase()));
    }

    onEnter(e) {
        if (this.username.val() == "" || this.pass.val() == "") {
            this.onRemoveDiv();
            this.error.append('<div id="validate" class="alert alert-danger" role="alert">O login e a senha devem ser preenchidos.</div>');
            return;
        }
        e.preventDefault();
        const protocol = window.location.protocol;
        let baseUrl = protocol + '//' + window.location.hostname;
        if (window.location.port != "") {
            baseUrl = baseUrl + ':' + window.location.port;
        }
        const querystring = this.getQuerystringStr();
        const qsState = querystring['state'] || '';
        let url = baseUrl + '/code_request?'+ querystring; 
        //let url = baseUrl + '/dados/code_request?' +
        //    'client_id=' + querystring['client_id'] +
        //    '&state=' + qsState +
        //    '&redirect_uri=' + querystring['redirect_uri'];
        $.ajax({
            url: url,
            crossDomain: true,
            contentType: 'application/json',
            beforeSend: function(xhr) {
                xhr.setRequestHeader("Authorization", "Basic " + btoa($('#username').val().trim() + ":" + $('#pass').val()));
            },
            error: this.onErroSalvandoEstilo.bind(this),
            success: function(data, textStatus, headers) {
                if (data.redirect) {
                    window.location.href = data.redirect;
                }
            },
            complete: function(data, textStatus) {
                if (textStatus == 'success') {
                    const referrer = document.referrer;
                    let urlLocation = data.getResponseHeader("Location");
                    if (referrer != undefined && referrer != "") {
                        const baseUrlReferrer = referrer.split('/');
                        urlLocation = baseUrlReferrer[0] + '//' + baseUrlReferrer[2] + urlLocation;
                    } else {
                        if (baseUrl.startsWith("/")) {
                            urlLocation = baseUrl + urlLocation;
                        }
                    }
                    window.location.href = urlLocation;
                }
            }
        });
    }

    onErroSalvandoEstilo(obj) {
        this.onRemoveDiv();
        this.error.append('<div id="validate" class="alert alert-danger" role="alert">Usuário ou senha inválido(s).</div>');
    }

    onEstiloSalvo(estilo) {
        this.error.append('<div class="alert alert-danger" role="alert">Ok.</div>');
    }

    onRemoveDiv() {
        const divElement = $("#validate");
        if (divElement != undefined) {
            divElement.remove("#validate");
        }
    }

	getQuerystringStr(){
		var href = window.location.href;
		var posQuerystring = href.indexOf('?');
		if (posQuerystring > 0){
			return href.slice(posQuerystring + 1);
		}
		else{
			return "";
		}
	}

  /*  getQs() {
        let qs = [];
        const href = window.location.href;
        const posQuerystring = href.indexOf('?');
        if (posQuerystring > 0) {
            let hashes = href.slice(posQuerystring + 1).split('&');
            for (let i = 0; i < hashes.length; i++) {
                const params = hashes[i].split('=');
                const paramName = params[0];
                qs.push(paramName);
                qs[paramName] = params[1];
            }
        }
        return qs;
    } */
};

$(function() {
    new Login();
});
