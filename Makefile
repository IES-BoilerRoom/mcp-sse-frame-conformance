.PHONY: check ci
check:
	python3 suite/validate_rfc8259_frames.py

ci:
	python3 suite/validate_rfc8259_frames.py --strict-ci
