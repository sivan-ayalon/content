function format_ip(ip) {
    return ip.replace(/\[\.\]/g,'.');
}

function format_ip_list(ip_list) {
    var len = ip_list.length;
    var formatted_ips = new Array(len);
    ip_list.forEach(function(the_ip, index) {
        the_ip = the_ip.trim()
        the_ip = isNaN(the_ip[0]) ? the_ip.slice(1,) : the_ip  // Will remove non number char from beginning of IPv4
        the_ip = isNaN(the_ip[the_ip.length-1]) ? the_ip.slice(0,-1) : the_ip  // Will remove non number char from end of IPv4
        formatted_ips[index] = format_ip(the_ip);
    });
    return formatted_ips;
}

var ips;
// It is assumed that args.input is a string
var unformatted_ips = argToList(args.input);
ips = format_ip_list(unformatted_ips);
return ips;
