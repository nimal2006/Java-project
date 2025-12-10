import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec; 
public class DocumentVerifierAWT_UI extends Frame {
// Storage layout
private static final String STORAGE_DIR = "storage";
private static final String RECORDS_FILE = "records.ser";
private static final String AUDIT_LOG = "audit.log";
private static final String KEY_FILE = "key.bin";
private static final String ADMIN_CREDS = "admin.creds";
private static final String DEFAULT_ADMIN_USER = "admin";
private static final String DEFAULT_ADMIN_PASS = "admin123";
// Crypto
private static final String AES_ALGO = "AES";
// UI
private CardLayout cardLayout = new CardLayout();
private Panel mainPanel = new Panel(cardLayout);

// Login components
private TextField loginUserField = new TextField(20);
private TextField loginRoleField = new TextField(20); // "user" or "admin"
private Label loginMessageLabel = new Label("", Label.CENTER);

// Dashboard components
private Label headerLabel = new Label("", Label.CENTER);
private TextArea activityLogArea = new TextArea("", 4, 60, TextArea.SCROLLBARS_VERTICAL_ONLY);

private String currentUser = "";
private String currentRole = "";

// Records in memory
private Map<String, DocRecord> records = new LinkedHashMap<>();

// AES key
private SecretKey aesKey;

// Date formatter
private static final SimpleDateFormat TS_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
private static final SimpleDateFormat FILE_TS_FORMAT = new SimpleDateFormat("yyyyMMddHHmmss");

// Data model
public static class DocRecord implements Serializable {
private static final long serialVersionUID = 1L;
String docId;
String originalName;
String storedBaseName;
String sha256;
java.util.List<String> statusHistory = new java.util.ArrayList<String>();
java.util.List<String> versions = new java.util.ArrayList<String>();
}

public DocumentVerifierAWT_UI() {
super("Document Verification & Tracking System");
setSize(900, 600);
setLocationRelativeTo(null);
setLayout(new BorderLayout());
initStorageAndSecurity();
loadRecords();
prepareGUI();
}

// Center frame on screen
public void setLocationRelativeTo(Component c) {
Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
int x = (screen.width - getWidth()) / 2;
int y = (screen.height - getHeight()) / 2;
setLocation(x, y);
}

// Prepare storage, AES key, and default admin creds
private void initStorageAndSecurity() {
try {
File dir = new File(STORAGE_DIR);
if (!dir.exists()) {
dir.mkdirs();
}
// AES key
File keyFile = new File(KEY_FILE);
if (!keyFile.exists()) {
KeyGenerator kg = KeyGenerator.getInstance(AES_ALGO);
kg.init(128);
SecretKey key = kg.generateKey();
byte[] keyBytes = key.getEncoded();
try (FileOutputStream fos = new FileOutputStream(keyFile)) {
fos.write(keyBytes);
}
}
byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
aesKey = new SecretKeySpec(keyBytes, AES_ALGO);

// Admin creds
File creds = new File(ADMIN_CREDS);
     if (!creds.exists()) {
         saveAdminCreds(DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS);
     }
 } catch (Exception e) {
     e.printStackTrace();
     showErrorDialog("Initialization error: " + e.getMessage());
 }
}

private void saveAdminCreds(String user, String plainPass) throws Exception {
String hash = sha256String(plainPass);
Properties p = new Properties();
p.setProperty("user", user);
p.setProperty("hash", hash);
try (FileOutputStream fos = new FileOutputStream(ADMIN_CREDS)) {
p.store(fos, "Admin credentials");
}
}

private boolean checkAdminCreds(String user, String plainPass) {
Properties p = new Properties();
try (FileInputStream fis = new FileInputStream(ADMIN_CREDS)) {
p.load(fis);
String u = p.getProperty("user", "");
String h = p.getProperty("hash", "");
String inputHash = sha256String(plainPass);
return user.equals(u) && inputHash.equals(h);
} catch (Exception e) {
return false;
}
}

// UI setup
private void prepareGUI() {
// Frame close
addWindowListener(new WindowAdapter() {
public void windowClosing(WindowEvent e) {
dispose();
System.exit(0);
}
});

Panel loginPanel = buildLoginPanel();
 Panel dashboardPanel = buildDashboardPanel();

 mainPanel.add(loginPanel, "login");
 mainPanel.add(dashboardPanel, "dashboard");

 add(mainPanel, BorderLayout.CENTER);
 cardLayout.show(mainPanel, "login");
}

private Panel buildLoginPanel() {
Panel panel = new Panel() {
public void paint(Graphics g) {
super.paint(g);
// tinted blue background
g.setColor(new Color(190, 210, 255));
g.fillRect(0, 0, getWidth(), getHeight());
}
};
panel.setLayout(new GridBagLayout());

Label title = new Label("DOCUMENT SYSTEM LOGIN", Label.CENTER);
 title.setFont(new Font("SansSerif", Font.BOLD, 26));
 title.setForeground(new Color(30, 30, 70));

 Label userLabel = new Label("Username:");
 userLabel.setFont(new Font("SansSerif", Font.PLAIN, 16));
 loginUserField.setFont(new Font("SansSerif", Font.PLAIN, 16));

 Label roleLabel = new Label("Role (user/admin):");
 roleLabel.setFont(new Font("SansSerif", Font.PLAIN, 16));
 loginRoleField.setFont(new Font("SansSerif", Font.PLAIN, 16));

 Button loginButton = new Button("Login");
 loginButton.setBackground(new Color(60, 180, 90));
 loginButton.setForeground(Color.white);
 loginButton.setFont(new Font("SansSerif", Font.BOLD, 18));

 loginMessageLabel.setFont(new Font("SansSerif", Font.PLAIN, 14));
 loginMessageLabel.setForeground(Color.red);

 GridBagConstraints gbc = new GridBagConstraints();
 gbc.insets = new Insets(10, 10, 10, 10);
 gbc.gridx = 0;
 gbc.gridy = 0;
 gbc.gridwidth = 2;
 gbc.anchor = GridBagConstraints.CENTER;
 panel.add(title, gbc);

 gbc.gridwidth = 1;
 gbc.gridy++;
 gbc.anchor = GridBagConstraints.EAST;
 panel.add(userLabel, gbc);

 gbc.gridx = 1;
 gbc.anchor = GridBagConstraints.WEST;
 panel.add(loginUserField, gbc);

 gbc.gridx = 0;
 gbc.gridy++;
 gbc.anchor = GridBagConstraints.EAST;
 panel.add(roleLabel, gbc);

 gbc.gridx = 1;
 gbc.anchor = GridBagConstraints.WEST;
 panel.add(loginRoleField, gbc);

 gbc.gridx = 0;
 gbc.gridy++;
 gbc.gridwidth = 2;
 gbc.anchor = GridBagConstraints.CENTER;
 panel.add(loginButton, gbc);

 gbc.gridy++;
 panel.add(loginMessageLabel, gbc);

 loginButton.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         handleLogin();
     }
 });

 return panel;
}

private Panel buildDashboardPanel() {
Panel root = new Panel(new BorderLayout());

// Top header
 Panel headerPanel = new Panel(new BorderLayout());
 headerPanel.setBackground(new Color(120, 70, 160));
 headerLabel.setFont(new Font("SansSerif", Font.BOLD, 24));
 headerLabel.setForeground(Color.white);
 headerPanel.add(headerLabel, BorderLayout.CENTER);
 root.add(headerPanel, BorderLayout.NORTH);

 // Center dashboard buttons
 Panel centerPanel = new Panel(new GridBagLayout());
 centerPanel.setBackground(new Color(240, 240, 255));
 GridBagConstraints gbc = new GridBagConstraints();
 gbc.insets = new Insets(20, 40, 20, 40);
 gbc.fill = GridBagConstraints.BOTH;
 gbc.weightx = 1.0;
 gbc.weighty = 1.0;

 Button uploadBtn = createBigButton("Upload Document", new Color(255, 140, 0));
 Button trackBtn = createBigButton("Track Status", new Color(60, 180, 90));
 Button profileBtn = createBigButton("Profile", new Color(70, 120, 220));
 Button logoutBtn = createBigButton("Logout", new Color(200, 60, 60));

 gbc.gridx = 0;
 gbc.gridy = 0;
 centerPanel.add(uploadBtn, gbc);
 gbc.gridx = 1;
 centerPanel.add(trackBtn, gbc);

 gbc.gridx = 0;
 gbc.gridy = 1;
 centerPanel.add(profileBtn, gbc);
 gbc.gridx = 1;
 centerPanel.add(logoutBtn, gbc);

 root.add(centerPanel, BorderLayout.CENTER);

 // Bottom activity log
 Panel bottomPanel = new Panel(new BorderLayout());
 Label logLabel = new Label("Activity Log", Label.LEFT);
 logLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
 bottomPanel.add(logLabel, BorderLayout.NORTH);
 activityLogArea.setEditable(false);
 activityLogArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
 bottomPanel.add(activityLogArea, BorderLayout.CENTER);
 bottomPanel.setPreferredSize(new Dimension(800, 120));
 root.add(bottomPanel, BorderLayout.SOUTH);

 uploadBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         showUploadDialog();
     }
 });
 trackBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         showTrackDialog();
     }
 });
 profileBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         showProfileDialog();
     }
 });
 logoutBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         currentUser = "";
         currentRole = "";
         headerLabel.setText("");
         activityLogArea.setText("");
         cardLayout.show(mainPanel, "login");
     }
 });

 return root;
}

private Button createBigButton(String text, Color bg) {
Button b = new Button(text);
b.setBackground(bg);
b.setForeground(Color.white);
b.setFont(new Font("SansSerif", Font.BOLD, 18));
return b;
}

// Login handling
private void handleLogin() {
String user = loginUserField.getText().trim();
String role = loginRoleField.getText().trim().toLowerCase(Locale.ENGLISH);
if (user.isEmpty() || role.isEmpty()) {
loginMessageLabel.setText("Enter username and role.");
return;
}
if (!role.equals("user") && !role.equals("admin")) {
loginMessageLabel.setText("Role must be 'user' or 'admin'.");
return;
}
if (role.equals("admin")) {
// prompt admin password
AdminLoginDialog d = new AdminLoginDialog(this);
d.setVisible(true);
if (!d.isAuthenticated()) {
loginMessageLabel.setText("Admin authentication failed.");
return;
}
}
currentUser = user;
currentRole = role;
headerLabel.setText("Welcome, " + currentUser);
activityLogArea.setText("");
loginMessageLabel.setText("");
cardLayout.show(mainPanel, "dashboard");
appendActivity("Logged in as " + currentUser + " (" + currentRole + ")");
}

// Upload document
private void showUploadDialog() {
Dialog dialog = new Dialog(this, "Upload Document", true);
dialog.setSize(500, 300);
dialog.setLayout(new GridBagLayout());
centerDialog(dialog);

Label fileLabel = new Label("Selected File:");
 TextField fileField = new TextField(25);
 fileField.setEditable(false);
 Button browseBtn = new Button("Browse...");
 Label docIdLabel = new Label("Document ID:");
 TextField docIdField = new TextField(20);
 Button submitBtn = new Button("Submit");
 Label msgLabel = new Label("", Label.CENTER);
 msgLabel.setForeground(Color.red);

 GridBagConstraints gbc = new GridBagConstraints();
 gbc.insets = new Insets(10, 10, 10, 10);
 gbc.gridx = 0;
 gbc.gridy = 0;
 gbc.anchor = GridBagConstraints.EAST;
 dialog.add(fileLabel, gbc);

 gbc.gridx = 1;
 gbc.anchor = GridBagConstraints.WEST;
 dialog.add(fileField, gbc);

 gbc.gridx = 2;
 dialog.add(browseBtn, gbc);

 gbc.gridx = 0;
 gbc.gridy++;
 gbc.anchor = GridBagConstraints.EAST;
 dialog.add(docIdLabel, gbc);

 gbc.gridx = 1;
 gbc.gridwidth = 2;
 gbc.anchor = GridBagConstraints.WEST;
 dialog.add(docIdField, gbc);

 gbc.gridx = 0;
 gbc.gridy++;
 gbc.gridwidth = 3;
 gbc.anchor = GridBagConstraints.CENTER;
 dialog.add(submitBtn, gbc);

 gbc.gridy++;
 dialog.add(msgLabel, gbc);

 browseBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         FileDialog fd = new FileDialog(dialog, "Choose File", FileDialog.LOAD);
         fd.setVisible(true);
         String file = fd.getFile();
         String dir = fd.getDirectory();
         if (file != null && dir != null) {
             fileField.setText(dir + file);
             if (docIdField.getText().trim().isEmpty()) {
                 String base = file;
                 int idx = base.lastIndexOf('.');
                 if (idx > 0) base = base.substring(0, idx);
                 docIdField.setText(base.toUpperCase(Locale.ENGLISH));
             }
         }
     }
 });

 submitBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         String path = fileField.getText().trim();
         String docId = docIdField.getText().trim();
         if (path.isEmpty() || docId.isEmpty()) {
             msgLabel.setText("Select file and enter Document ID.");
             return;
         }
         File f = new File(path);
         if (!f.exists()) {
             msgLabel.setText("File does not exist.");
             return;
         }
         submitAndStore(dialog, f, docId, msgLabel);
     }
 });

 dialog.addWindowListener(new WindowAdapter() {
     public void windowClosing(WindowEvent e) {
         dialog.dispose();
     }
 });

 dialog.setVisible(true);
}

private void submitAndStore(Dialog dialog, File file, String docId, Label msgLabel) {
try {
String sha = sha256File(file);
// Duplicate detection
String existingDocId = findDocIdByHash(sha);
if (existingDocId != null && !existingDocId.equals(docId)) {
boolean proceed = confirmDialog(dialog,
"Duplicate detected. Existing Doc ID: " + existingDocId + ". Proceed anyway?");
if (!proceed) {
msgLabel.setText("Upload cancelled due to duplicate.");
return;
}
}
DocRecord rec = records.get(docId);
if (rec == null) {
rec = new DocRecord();
rec.docId = docId;
rec.originalName = file.getName();
rec.storedBaseName = docId + "" + System.currentTimeMillis();
rec.sha256 = sha;
records.put(docId, rec);
} else {
rec.sha256 = sha; // update hash to latest upload
if (rec.originalName == null) {
rec.originalName = file.getName();
}
}
String timestamp = FILE_TS_FORMAT.format(new Date());
String encName = docId + "" + file.getName().replaceAll("\s+", "") + "" + timestamp + ".enc";
File dest = new File(STORAGE_DIR, encName);
encryptFile(file, dest);
rec.versions.add(encName);
String statusEntry = timestamp() + "|SUBMITTED|" + currentUser + "|File uploaded";
rec.statusHistory.add(statusEntry);
saveRecords();
appendAudit(currentUser, "UPLOAD", docId + "|" + file.getName());
appendActivity("Uploaded " + file.getName() + " as " + docId);
msgLabel.setText("Upload successful.");
} catch (Exception ex) {
ex.printStackTrace();
msgLabel.setText("Error: " + ex.getMessage());
}
}

private String findDocIdByHash(String sha) {
for (DocRecord r : records.values()) {
if (sha.equals(r.sha256)) {
return r.docId;
}
}
return null;
}

// Track dialog
private void showTrackDialog() {
Dialog dialog = new Dialog(this, "Track Document", true);
dialog.setSize(650, 400);
dialog.setLayout(new GridBagLayout());
centerDialog(dialog);

Label idLabel = new Label("Document ID:");
 TextField idField = new TextField(20);
 Button searchBtn = new Button("Search");
 TextArea infoArea = new TextArea("", 10, 60, TextArea.SCROLLBARS_VERTICAL_ONLY);
 infoArea.setEditable(false);

 Button downloadBtn = new Button("Download Latest");
 Button approveBtn = new Button("Approve");
 Button rejectBtn = new Button("Reject");

 Label msgLabel = new Label("", Label.CENTER);
 msgLabel.setForeground(Color.red);

 GridBagConstraints gbc = new GridBagConstraints();
 gbc.insets = new Insets(10, 10, 5, 10);
 gbc.gridx = 0;
 gbc.gridy = 0;
 gbc.anchor = GridBagConstraints.EAST;
 dialog.add(idLabel, gbc);

 gbc.gridx = 1;
 gbc.anchor = GridBagConstraints.WEST;
 dialog.add(idField, gbc);

 gbc.gridx = 2;
 dialog.add(searchBtn, gbc);

 gbc.gridx = 0;
 gbc.gridy++;
 gbc.gridwidth = 3;
 gbc.fill = GridBagConstraints.BOTH;
 gbc.weightx = 1.0;
 gbc.weighty = 1.0;
 dialog.add(infoArea, gbc);

 Panel buttonPanel = new Panel(new FlowLayout(FlowLayout.CENTER, 20, 5));
 buttonPanel.add(downloadBtn);
 buttonPanel.add(approveBtn);
 buttonPanel.add(rejectBtn);

 gbc.gridy++;
 gbc.weighty = 0;
 gbc.fill = GridBagConstraints.NONE;
 dialog.add(buttonPanel, gbc);

 gbc.gridy++;
 dialog.add(msgLabel, gbc);

 approveBtn.setEnabled("admin".equals(currentRole));
 rejectBtn.setEnabled("admin".equals(currentRole));

 searchBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         String docId = idField.getText().trim();
         DocRecord rec = records.get(docId);
         if (rec == null) {
             infoArea.setText("");
             msgLabel.setText("Document not found.");
         } else {
             msgLabel.setText("");
             infoArea.setText(formatRecordInfo(rec));
         }
     }
 });

 downloadBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         String docId = idField.getText().trim();
         DocRecord rec = records.get(docId);
         if (rec == null) {
             msgLabel.setText("Document not found.");
             return;
         }
         try {
             downloadLatest(dialog, rec);
             msgLabel.setText("Download completed.");
         } catch (Exception ex) {
             msgLabel.setText("Download failed: " + ex.getMessage());
         }
     }
 });

 approveBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         String docId = idField.getText().trim();
         DocRecord rec = records.get(docId);
         if (rec == null) {
             msgLabel.setText("Document not found.");
             return;
         }
         adminAction(rec, "APPROVED", "Approved by admin");
         infoArea.setText(formatRecordInfo(rec));
         msgLabel.setText("Approved.");
     }
 });

 rejectBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         String docId = idField.getText().trim();
         DocRecord rec = records.get(docId);
         if (rec == null) {
             msgLabel.setText("Document not found.");
             return;
         }
         adminAction(rec, "REJECTED", "Rejected by admin");
         infoArea.setText(formatRecordInfo(rec));
         msgLabel.setText("Rejected.");
     }
 });

 dialog.addWindowListener(new WindowAdapter() {
     public void windowClosing(WindowEvent e) {
         dialog.dispose();
     }
 });

 dialog.setVisible(true);
}

private String formatRecordInfo(DocRecord rec) {
StringBuilder sb = new StringBuilder();
sb.append("Document ID: ").append(rec.docId).append("\n");
sb.append("Original Name: ").append(rec.originalName).append("\n");
sb.append("SHA-256: ").append(rec.sha256).append("\n");
sb.append("Stored Base: ").append(rec.storedBaseName).append("\n");
sb.append("Versions:\n");
for (String v : rec.versions) {
sb.append(" - ").append(v).append("\n");
}
sb.append("Status History:\n");
for (String s : rec.statusHistory) {
sb.append(" - ").append(s).append("\n");
}
return sb.toString();
}

private void adminAction(DocRecord rec, String status, String note) {
if (!"admin".equals(currentRole)) {
showErrorDialog("Only admin can perform this action.");
return;
}
String entry = timestamp() + "|" + status + "|" + currentUser + "|" + note;
rec.statusHistory.add(entry);
try {
saveRecords();
appendAudit(currentUser, status, rec.docId + "|" + note);
appendActivity(status + " " + rec.docId);
} catch (Exception e) {
e.printStackTrace();
showErrorDialog("Failed to update record: " + e.getMessage());
}
}

// Download latest version
private void downloadLatest(Dialog parent, DocRecord rec) throws Exception {
if (rec.versions.isEmpty()) {
showErrorDialog("No versions available.");
return;
}
String latest = rec.versions.get(rec.versions.size() - 1);
File encFile = new File(STORAGE_DIR, latest);

FileDialog fd = new FileDialog(parent, "Save Decrypted File As", FileDialog.SAVE);
 fd.setFile(rec.originalName != null ? rec.originalName : "document.bin");
 fd.setVisible(true);
 String file = fd.getFile();
 String dir = fd.getDirectory();
 if (file == null || dir == null) {
     return;
 }
 File dest = new File(dir, file);
 decryptFile(encFile, dest);
 appendAudit(currentUser, "DOWNLOAD", rec.docId + "|" + dest.getAbsolutePath());
 appendActivity("Downloaded latest version of " + rec.docId);
}

// Profile dialog
private void showProfileDialog() {
Dialog dialog = new Dialog(this, "Profile", true);
dialog.setSize(450, 260);
dialog.setLayout(new GridBagLayout());
centerDialog(dialog);

Label infoLabel = new Label("Logged in as: " + currentUser + " (" + currentRole + ")", Label.CENTER);
 infoLabel.setFont(new Font("SansSerif", Font.BOLD, 16));

 Label oldPassLabel = new Label("Current Admin Password:");
 TextField oldPassField = new TextField(20);
 oldPassField.setEchoChar('*');

 Label newPassLabel = new Label("New Admin Password:");
 TextField newPassField = new TextField(20);
 newPassField.setEchoChar('*');

 Button changeBtn = new Button("Change Password");
 Button exportBtn = new Button("Export Records CSV");
 Label msgLabel = new Label("", Label.CENTER);
 msgLabel.setForeground(Color.red);

 GridBagConstraints gbc = new GridBagConstraints();
 gbc.insets = new Insets(10, 10, 5, 10);
 gbc.gridx = 0;
 gbc.gridy = 0;
 gbc.gridwidth = 2;
 gbc.anchor = GridBagConstraints.CENTER;
 dialog.add(infoLabel, gbc);

 gbc.gridwidth = 1;
 gbc.gridy++;
 gbc.anchor = GridBagConstraints.EAST;
 dialog.add(oldPassLabel, gbc);
 gbc.gridx = 1;
 gbc.anchor = GridBagConstraints.WEST;
 dialog.add(oldPassField, gbc);

 gbc.gridx = 0;
 gbc.gridy++;
 gbc.anchor = GridBagConstraints.EAST;
 dialog.add(newPassLabel, gbc);
 gbc.gridx = 1;
 gbc.anchor = GridBagConstraints.WEST;
 dialog.add(newPassField, gbc);

 Panel buttonPanel = new Panel(new FlowLayout(FlowLayout.CENTER, 15, 5));
 buttonPanel.add(changeBtn);
 buttonPanel.add(exportBtn);

 gbc.gridx = 0;
 gbc.gridy++;
 gbc.gridwidth = 2;
 gbc.anchor = GridBagConstraints.CENTER;
 dialog.add(buttonPanel, gbc);

 gbc.gridy++;
 dialog.add(msgLabel, gbc);

 // Only admin can change password
 oldPassField.setEnabled("admin".equals(currentRole));
 newPassField.setEnabled("admin".equals(currentRole));
 changeBtn.setEnabled("admin".equals(currentRole));

 changeBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         if (!"admin".equals(currentRole)) {
             msgLabel.setText("Only admin can change password.");
             return;
         }
         String oldP = oldPassField.getText();
         String newP = newPassField.getText();
         if (oldP.isEmpty() || newP.isEmpty()) {
             msgLabel.setText("Enter both current and new password.");
             return;
         }
         if (!checkAdminCreds(DEFAULT_ADMIN_USER, oldP) && !checkAdminCreds(currentUser, oldP)) {
             msgLabel.setText("Current password incorrect.");
             return;
         }
         try {
             saveAdminCreds(currentUser, newP);
             appendAudit(currentUser, "PASSWORD_CHANGE", "Admin password changed");
             appendActivity("Admin password changed.");
             msgLabel.setText("Password changed successfully.");
         } catch (Exception ex) {
             msgLabel.setText("Failed: " + ex.getMessage());
         }
     }
 });

 exportBtn.addActionListener(new ActionListener() {
     public void actionPerformed(ActionEvent e) {
         try {
             exportRecordsToCSV(dialog);
             msgLabel.setText("Export completed.");
         } catch (Exception ex) {
             msgLabel.setText("Export failed: " + ex.getMessage());
         }
     }
 });

 dialog.addWindowListener(new WindowAdapter() {
     public void windowClosing(WindowEvent e) {
         dialog.dispose();
     }
 });

 dialog.setVisible(true);
}

private void exportRecordsToCSV(Dialog parent) throws IOException {
FileDialog fd = new FileDialog(parent, "Export CSV", FileDialog.SAVE);
fd.setFile("records_export.csv");
fd.setVisible(true);
String file = fd.getFile();
String dir = fd.getDirectory();
if (file == null || dir == null) return;
File out = new File(dir, file);
try (PrintWriter pw = new PrintWriter(new FileWriter(out))) {
pw.println("docId,originalName,storedBaseName,sha256,versions,statusHistory");
for (DocRecord r : records.values()) {
String versionsJoined = String.join(";", r.versions);
String statusJoined = String.join(";", r.statusHistory);
pw.println(escapeCsv(r.docId) + ","
+ escapeCsv(r.originalName) + ","
+ escapeCsv(r.storedBaseName) + ","
+ escapeCsv(r.sha256) + ","
+ escapeCsv(versionsJoined) + ","
+ escapeCsv(statusJoined));
}
}
appendAudit(currentUser, "EXPORT_CSV", out.getAbsolutePath());
appendActivity("Exported records to CSV.");
}

private String escapeCsv(String s) {
if (s == null) return "";
if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
return "\"" + s.replace("\"", "\"\"") + "\"";
}
return s;
}

// Records persistence
private void loadRecords() {
File f = new File(RECORDS_FILE);
if (!f.exists()) {
records = new LinkedHashMap<String, DocRecord>();
return;
}
try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
Object o = ois.readObject();
if (o instanceof Map) {
@SuppressWarnings("unchecked")
Map<String, DocRecord> m = (Map<String, DocRecord>) o;
records = m;
} else {
records = new LinkedHashMap<String, DocRecord>();
}
} catch (Exception e) {
e.printStackTrace();
records = new LinkedHashMap<String, DocRecord>();
}
}

private void saveRecords() throws IOException {
try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(RECORDS_FILE))) {
oos.writeObject(records);
}
}

// Audit log
private void appendAudit(String actor, String action, String detail) {
String line = timestamp() + "|" + actor + "|" + action + "|" + detail;
try (FileWriter fw = new FileWriter(AUDIT_LOG, true);
BufferedWriter bw = new BufferedWriter(fw)) {
bw.write(line);
bw.newLine();
} catch (IOException e) {
e.printStackTrace();
}
}

private void appendActivity(String s) {
activityLogArea.append(timestamp() + " - " + s + "\n");
}

private String timestamp() {
return TS_FORMAT.format(new Date());
}

// Crypto helpers
private String sha256String(String data) throws Exception {
MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] hash = md.digest(data.getBytes("UTF-8"));
return bytesToHex(hash);
}

private String sha256File(File file) throws Exception {
MessageDigest md = MessageDigest.getInstance("SHA-256");
try (InputStream is = new FileInputStream(file)) {
byte[] buf = new byte[8192];
int r;
while ((r = is.read(buf)) != -1) {
md.update(buf, 0, r);
}
}
byte[] hash = md.digest();
return bytesToHex(hash);
}

private void encryptFile(File in, File out) throws Exception {
Cipher cipher = Cipher.getInstance(AES_ALGO);
cipher.init(Cipher.ENCRYPT_MODE, aesKey);
try (FileInputStream fis = new FileInputStream(in);
FileOutputStream fos = new FileOutputStream(out);
CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
byte[] buf = new byte[8192];
int r;
while ((r = fis.read(buf)) != -1) {
cos.write(buf, 0, r);
}
}
}

private void decryptFile(File in, File out) throws Exception {
Cipher cipher = Cipher.getInstance(AES_ALGO);
cipher.init(Cipher.DECRYPT_MODE, aesKey);
try (FileInputStream fis = new FileInputStream(in);
CipherInputStream cis = new CipherInputStream(fis, cipher);
FileOutputStream fos = new FileOutputStream(out)) {
byte[] buf = new byte[8192];
int r;
while ((r = cis.read(buf)) != -1) {
fos.write(buf, 0, r);
}
}
}

// Utils
private static String bytesToHex(byte[] b) {
StringBuilder sb = new StringBuilder();
for (byte value : b) {
String st = Integer.toHexString(value & 0xff);
if (st.length() == 1) sb.append('0');
sb.append(st);
}
return sb.toString();
}

private void showErrorDialog(String msg) {
Dialog d = new Dialog(this, "Error", true);
d.setSize(300, 150);
d.setLayout(new BorderLayout());
Label l = new Label(msg, Label.CENTER);
d.add(l, BorderLayout.CENTER);
Button ok = new Button("OK");
Panel p = new Panel();
p.add(ok);
d.add(p, BorderLayout.SOUTH);
centerDialog(d);
ok.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent e) {
d.dispose();
}
});
d.addWindowListener(new WindowAdapter() {
public void windowClosing(WindowEvent e) {
d.dispose();
}
});
d.setVisible(true);
}

private boolean confirmDialog(Dialog parent, String msg) {
final boolean[] result = new boolean[1];
Dialog d = new Dialog(parent, "Confirm", true);
d.setSize(350, 160);
d.setLayout(new BorderLayout());
Label l = new Label(msg, Label.CENTER);
d.add(l, BorderLayout.CENTER);
Panel p = new Panel();
Button yes = new Button("Yes");
Button no = new Button("No");
p.add(yes);
p.add(no);
d.add(p, BorderLayout.SOUTH);
centerDialog(d);
yes.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent e) {
result[0] = true;
d.dispose();
}
});
no.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent e) {
result[0] = false;
d.dispose();
}
});
d.addWindowListener(new WindowAdapter() {
public void windowClosing(WindowEvent e) {
result[0] = false;
d.dispose();
}
});
d.setVisible(true);
return result[0];
}

private void centerDialog(Dialog d) {
Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
int x = (screen.width - d.getWidth()) / 2;
int y = (screen.height - d.getHeight()) / 2;
d.setLocation(x, y);
}

// Admin login dialog
private class AdminLoginDialog extends Dialog {
private boolean authenticated = false;

public AdminLoginDialog(Frame parent) {
     super(parent, "Admin Authentication", true);
     setSize(350, 200);
     setLayout(new GridBagLayout());
     centerDialog(this);

     Label userLabel = new Label("Admin Username:");
     TextField userField = new TextField(20);
     userField.setText(DEFAULT_ADMIN_USER);
     Label passLabel = new Label("Admin Password:");
     TextField passField = new TextField(20);
     passField.setEchoChar('*');
     Button okBtn = new Button("Login");
     Button cancelBtn = new Button("Cancel");
     Label msgLabel = new Label("", Label.CENTER);
     msgLabel.setForeground(Color.red);

     GridBagConstraints gbc = new GridBagConstraints();
     gbc.insets = new Insets(10, 10, 5, 10);
     gbc.gridx = 0;
     gbc.gridy = 0;
     gbc.anchor = GridBagConstraints.EAST;
     add(userLabel, gbc);
     gbc.gridx = 1;
     gbc.anchor = GridBagConstraints.WEST;
     add(userField, gbc);

     gbc.gridx = 0;
     gbc.gridy++;
     gbc.anchor = GridBagConstraints.EAST;
     add(passLabel, gbc);
     gbc.gridx = 1;
     gbc.anchor = GridBagConstraints.WEST;
     add(passField, gbc);

     Panel bp = new Panel(new FlowLayout(FlowLayout.CENTER, 15, 5));
     bp.add(okBtn);
     bp.add(cancelBtn);
     gbc.gridx = 0;
     gbc.gridy++;
     gbc.gridwidth = 2;
     gbc.anchor = GridBagConstraints.CENTER;
     add(bp, gbc);

     gbc.gridy++;
     add(msgLabel, gbc);

     okBtn.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
             String u = userField.getText().trim();
             String p = passField.getText();
             if (checkAdminCreds(u, p)) {
                 authenticated = true;
                 dispose();
             } else {
                 msgLabel.setText("Invalid admin credentials.");
             }
         }
     });

     cancelBtn.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
             authenticated = false;
             dispose();
         }
     });

     addWindowListener(new WindowAdapter() {
         public void windowClosing(WindowEvent e) {
             authenticated = false;
             dispose();
         }
     });
 }

 public boolean isAuthenticated() {
     return authenticated;
 }
}

public static void main(String[] args) {
DocumentVerifierAWT_UI app = new DocumentVerifierAWT_UI();
app.setVisible(true);
}
}