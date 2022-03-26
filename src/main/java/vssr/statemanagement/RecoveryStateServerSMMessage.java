package vssr.statemanagement;

import java.io.ObjectInput;
import java.io.IOException;
import java.io.ObjectOutput;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.SMMessage;

public class RecoveryStateServerSMMessage extends SMMessage {
    public RecoveryStateServerSMMessage() {
    }
    
    public RecoveryStateServerSMMessage(int sender, int cid, int type, View view, int regency, int leader) {
        super(sender, cid, type, null, view, regency, leader);
    }
    
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
    }
    
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
    }
}
