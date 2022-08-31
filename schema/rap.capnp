@0xdaf4e052ef20ec03;

struct RequestSigrl {
	gid @0 :Text;
}

struct ResponseSigrl {
	code @0 :UInt32;
	rid @1 :Data; # TODO change to text ?
	srl @2 :Data;
}

struct RequestReport {
	aep @0 :Text;
}

struct ResponseReport {
	code @0 :UInt32;
	rid  @1 :Text;
	signature    @2 :Text;
	certificates @3 :Text;

	avr @4 :Data;

	# reportId    @4 :Text;
	# timestamp   @5 :Text;
	# version     @6 :UInt32;
	# quoteStatus @7 :Text;
	# quoteBody   @8 :Text;

	#nonce @9 :Text; # actually, should be 13 !
}

struct RAPMessage {
	union {
		empty @0 :Void;
		requestSigrl @1 :RequestSigrl;
		responseSigrl @2 :ResponseSigrl;
		requestReport @3 :RequestReport;
		responseReport @4 :ResponseReport;
	}
}
