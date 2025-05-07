// toggle between left and right
$('#collapse').click(function() {
    var icon = $('#collapse').children("i")
    if(icon.is('.fa-angle-double-right')) {
        icon.attr("class", "fas fa-angle-double-left");
    }
    else {
        icon.attr("class", "fas fa-angle-double-right");
    }
});

// handle click on nav-link
$('.nav-link').click(function() {
    // set url for nav-link in sidebar
    if($(this).is('.dyn-url')) {
        // save collapse state
        var collapsed = "collapsed=" + ($('.sidebar-mini').is('.sidebar-collapse') ? 1 : 0);
        var a = ($('.has-treeview').eq(0).is('.menu-open') ? 1 : 0);
        var b = ($('.has-treeview').eq(1).is('.menu-open') ? 1 : 0);
        var menuopen = "menuopen=" + (a + (b << 1));
        $(this).attr("href", "/core/" + $(this).attr('id') + "?" + getSidebarState());
    }

    // blur clicked nav-link
    $(this).blur();
});

// save collapse state
function getSidebarState() {
    var collapsed = "collapsed=" + ($('.sidebar-mini').is('.sidebar-collapse') ? 1 : 0);
    var a = ($('.has-treeview').eq(0).is('.menu-open') ? 1 : 0);
    var b = ($('.has-treeview').eq(1).is('.menu-open') ? 1 : 0);
    var menuopen = "menuopen=" + (a + (b << 1));
    return collapsed + "&" + menuopen;
}

// draw percentage
window.onload = function() {
    $('.chart').each(function() {
        $(this).load();
    });
}

$.fn.load = function() {
    var canvas = $(this).get(0);
    var percent = $(this).attr('percent');
    var color = $(this).attr('color');

    var p = 0;
    var timer = null;
    timer = setInterval(function() {
        canvas.width = canvas.width;  // clear canvas
        if(p > percent) {
        draw(canvas, percent, color);
        clearInterval(timer);
        }
        else {
        draw(canvas, p, color);
        p += 1;
        }
    }, 20);
}

function draw(canvas, percent, color) {
    var sa = - Math.PI / 2;
    var ea = sa + (Math.PI * 2) * percent / 100;

    var r = Math.min(canvas.width, canvas.height) / 2;

    var ctx = canvas.getContext('2d')

    ctx.textAlign = "center";
    ctx.font = "bold 22px Arial";
    ctx.fillStyle = color;
    ctx.fillText(percent, r, r + 5);

    var lineWidth = 10;
    ctx.lineWidth = lineWidth;
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.arc(r, r, r - lineWidth - 10, sa, ea, false);
    ctx.stroke();

    lineWidth = 2;
    ctx.lineWidth = lineWidth;
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.arc(r, r, r - lineWidth - 8, 0, 2 * Math.PI, false);
    ctx.stroke();
}
