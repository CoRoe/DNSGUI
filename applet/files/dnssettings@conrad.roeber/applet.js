const Applet = imports.ui.applet;
const Util = imports.misc.util;

function MyApplet(orientation, panel_height, instance_id) {
    this._init(orientation, panel_height, instance_id);
}

MyApplet.prototype = {
    __proto__: Applet.IconApplet.prototype,

    _init: function(orientation, panel_height, instance_id) {
        Applet.IconApplet.prototype._init.call(this, orientation, panel_height,
					       instance_id);

        this.set_applet_icon_name("network-server");
        this.set_applet_tooltip(_("Click here to check or modify DNS settings."));
    },

    on_applet_clicked: function() {
	// TODO: Do not use hard-coded path
        Util.spawn(["/usr/local/bin/dnsconf.py"]);
    }
};

function main(metadata, orientation, panel_height, instance_id) {
    return new MyApplet(orientation, panel_height, instance_id);
}
