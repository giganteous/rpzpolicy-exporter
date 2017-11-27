# Let's assume you have a checkout of pdns in $HOME/git/pdns
dnsmessage/dnsmessage.pb.go: dnsmessage.proto
	protoc --go_out dnsmessage $^
