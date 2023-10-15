vcl 4.1;

backend default {
    .host = "fetch";
    .port = "80";
}

sub vcl_recv {
    if (req.http.Authorization) {
        return(hash);
    }
}
