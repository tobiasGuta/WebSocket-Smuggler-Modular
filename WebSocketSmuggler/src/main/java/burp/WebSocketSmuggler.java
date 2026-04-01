package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public class WebSocketSmuggler implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private SmugglerUI ui;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("WebSocket Smuggler");

        SwingUtilities.invokeLater(() -> {
            ui = new SmugglerUI(api);
            api.userInterface().registerSuiteTab("WebSocket Smuggler", ui.getUI());
        });

        api.userInterface().registerContextMenuItemsProvider(this);

        api.extension().registerUnloadingHandler(() -> {
            if (ui != null) {
                ui.getEngine().stop();
                ui.saveConfig();
            }
        });

        api.logging().logToOutput("WebSocket Smuggler (Modular) Loaded.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<>();
        JMenuItem item = new JMenuItem("Send to WebSocket Smuggler");
        item.addActionListener(e -> {
            List<HttpRequestResponse> selection = event.selectedRequestResponses();
            if (selection != null && !selection.isEmpty() && ui != null) {
                ui.setTargetAndAttack(selection.get(0));
            }
        });
        menuList.add(item);
        return menuList;
    }
}
