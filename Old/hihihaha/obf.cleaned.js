
var wanted1="58b4cb64f141e5c914640c5c8cc8e5d5"; // 20231114
var wanted2="8a1828526galf607b8257cb552b0e6c8"; // fL46
var wanted3="z99za5c140689zc2d2a1052c8z5e4b9d"; // Dec0d3


function setWindowSize() {
    window.resizeTo(500, 400);
}


setWindowSize();
window.onresize = setWindowSize;

var nl = [0, 6, 17, 14, 1, 18, 16, 7, 11, 13, 8, 12, 2, 3, 0, 15, 4, 0, 9, 5, 0, 0, 10, 0, 0];

function checkPW(pass) {
    if (pass != null && pass == 'close') {
        window.close();
    }
    var pwbody = (' ' + pass).split('');
    var h1 = '', h2 = '', h3 = '';
    for (var i = 0; i < 24;) {
        h1 += pwbody[nl[++i]];
        h2 += pwbody[nl[++i]];
        h3 += pwbody[nl[++i]];
    }
    // strip đầu và cuối string bỏ hết khoảng trắng thừa, sau đó lấy md5 cho vào hàm check
    if (check1(md5(h1.replace(/(^\s+)|(\s+$)/g, ''))) 
        && 
        check2(md5(h2.replace(/(^\s+)|(\s+$)/g, ''))) 
        && 
        check3(md5(h3.replace(/(^\s+)|(\s+$)/g, '')))) {
        alert('Congratulations! You got the right flag!');
        window.close();
    } else {
        alert('YOU\'RE WRONG, TRY AGAIN!');
        return;
    }
}



function check1(user_input1) {
    // find all to replace
    // 4 => a
    // d => 3
    // e => 7
    return user_input1 === reverseStr(wanted1.replace(/4/g, 'a').replace(/d/g, '3').replace(/e/g, '7'));
}
function check2(user_input2) {
    // f => 3
    // l => d
    // g => 9
    return user_input2 === reverseStr(wanted2.replace(/f/g, '3').replace(/l/g, 'd').replace(/g/g, '9'));
}
function check3(user_input3) {
    // 2 => f
    // b => 7
    // z => 3
    return user_input3 === reverseStr(wanted3.replace(/2/g, 'f').replace(/b/g, '7').replace(/z/g, '3'));
}
function reverseStr(string) {
    ver = string.split('').reverse().join('');
    return ver;
}