  var nl = [0, 6, 17, 14, 1, 18, 16, 7, 11, 13, 8, 12, 2, 3, 0, 15, 4, 0, 9, 5, 0, 0, 10, 0, 0];
  
  
  var pass = "1234567890ABCDEFGH"
  // 20231114fL46
  
  var pwbody = (' ' + pass).split('');
  console.log(pwbody)
    var h1 = '', h2 = '', h3 = '';
    for (var i = 0; i < 24;) {
        h1 += pwbody[nl[++i]];
        h2 += pwbody[nl[++i]];
        h3 += pwbody[nl[++i]];
    }

  console.log(h1)
  console.log(h2)
  console.log(h3)
