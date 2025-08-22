setup:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt

run-sniffer:
	. .venv/bin/activate && sudo python3 ids/sniff.py

run-hids:
	. .venv/bin/activate && python3 ids/hids.py

dashboard:
	. .venv/bin/activate && streamlit run ids/app_streamlit.py

