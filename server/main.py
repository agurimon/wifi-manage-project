from flask import Flask, render_template, request

app = Flask(__name__)

ap_list = []

bb = [{'Bbsid': 'test1', 'Essid': 'test2', 'Station_list': ['123', '123', '123']}]


@app.route("/")
def index():
    for ap in ap_list:
        print(ap)

    return render_template("index.html", ap_list=ap_list, enumerate=enumerate)


@app.route("/post", methods=["POST"])
def post():
    value = request.json
    
    exist = False
    station_exist = False
    for ap in ap_list:
        if ap['Bbsid'] == value['Bbsid']:
            exist = True

            for val_station in value['Station_list']:
                if val_station['Mac'] in ap['Station_list']:
                    station_exist = True

            if not station_exist:
                llist = []
                for mac_dict in value['Station_list']:
                    llist.append(mac_dict['Mac'])

                ap['Station_list'] = llist
    
    if not exist:
        station_list = []
        for mac_dict in value['Station_list']:
            station_list.append(mac_dict['Mac'])

        ap_list.append(
            {
                'Bbsid': value['Bbsid'], 
                'Essid': value['Essid'],
                'Channel': value['Channel'],
                'Station_list': station_list
            }
        )

    return ""


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)
