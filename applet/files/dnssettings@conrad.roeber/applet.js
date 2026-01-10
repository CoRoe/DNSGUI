const Applet = imports.ui.applet;
const Util = imports.misc.util;

class MyApplet extends Applet.TextIconApplet {
    constructor(metadata, orientation, panelHeight, instanceId) {
        super(orientation, panelHeight, instanceId);

        this.setAllowedLayout(Applet.AllowedLayout.BOTH);

        // Label
        // this.set_applet_label("Configure DNS resolver");

        // Custom icon (absolute path)
        this.set_applet_icon_path(
            metadata.path + "/dnsgui.png"
        );

        this.set_applet_tooltip("Configure DNS resolver");
    }

    on_applet_clicked() {
	Util.spawn(["/usr/local/bin/dnsconf.py"]);
    }
}

function main(metadata, orientation, panelHeight, instanceId) {
    return new MyApplet(metadata, orientation, panelHeight, instanceId);
}
