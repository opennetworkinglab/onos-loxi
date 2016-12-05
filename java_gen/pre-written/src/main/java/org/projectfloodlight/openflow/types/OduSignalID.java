/*
 * Copyright  2015, ECI Telecom, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 */
package org.projectfloodlight.openflow.types;


import java.util.List;

import io.netty.buffer.ByteBuf;

import com.google.common.collect.ComparisonChain;
import com.google.common.primitives.UnsignedBytes;
import com.google.common.hash.PrimitiveSink;

import org.projectfloodlight.openflow.exceptions.OFParseError;
import org.projectfloodlight.openflow.protocol.*;
import com.google.common.hash.Funnel;
import org.projectfloodlight.openflow.util.*;
import java.util.Arrays;

public class OduSignalID implements OFValueType<OduSignalID> {

    // version: 1.3
    final static byte WIRE_VERSION  = 4;
    final static int MINIMUM_LENGTH = 4;

        private final static int DEFAULT_TPN = 0x0;
        private final static int DEFAULT_TSLEN = 80;
        private final static byte[] DEFAULT_TSMAP = new byte[10];

    // OF message fields
    private final int tpn;
    private final int tslen;
    private final byte[] tsmap;
 
   // Immutable default instance
    public final static  OduSignalID DEFAULT = new  OduSignalID(
        DEFAULT_TPN, DEFAULT_TSLEN, DEFAULT_TSMAP
    );

    // package private constructor - used by readers, builders, and factory
     public OduSignalID(int tpn, int tslen, byte[] tsmap) {
        this.tpn = tpn;
        this.tslen = tslen;
        this.tsmap = tsmap;
    }

    public int getTpn() {
        return tpn;
    }

    public int getTslen() {
        return tslen;
    }

    public byte[] getTsmap() {
        return tsmap;
    }


    @Override
    public int getLength() {
      return MINIMUM_LENGTH + 12; //  tslen == 80 
    }
 
    public void writeTo(ByteBuf c) {
        c.writeShort(tpn);
        c.writeShort(tslen);
        c.writeBytes(tsmap); // 10 bytes
        c.writeZero(2); // write bytes for add padding alignment (the size of bytes in tsmap must be divided in 4)   
    }

     public static OduSignalID readFrom(ByteBuf c)   {
        int tpn = U16.f(c.readShort());
        int tslen = U16.f(c.readShort());
        byte[] tsmap = null;
        tsmap =ChannelUtils.readBytes(c, 10);
        ChannelUtils.readBytes(c, 2); // skip padding 
        OduSignalID oduSigId = new  OduSignalID(
                    tpn,
                      tslen,
                      tsmap
                    );
          return oduSigId;
    }


    public void putTo(PrimitiveSink sink) {
        FUNNEL.funnel(this, sink);
    }

    final static  OduSignalIDFunnel FUNNEL = new  OduSignalIDFunnel();
    static class  OduSignalIDFunnel implements Funnel< OduSignalID> {
        private static final long serialVersionUID = 1L;
        @Override
        public void funnel( OduSignalID message, PrimitiveSink sink) {
            sink.putInt(message.tpn);
            sink.putInt(message.tslen);
            sink.putBytes(message.tsmap);
        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder(" OduSignalID(");
        b.append("tpn=").append(tpn);
        b.append(", ");
        b.append("tslen=").append(tslen);
        b.append(", ");
        b.append("tsmap=").append(Arrays.toString(tsmap));
        b.append(")");
        return b.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
         OduSignalID other = (OduSignalID) obj;

        if( tpn != other.tpn)
            return false;
        if( tslen != other.tslen)
            return false;
        if (!Arrays.equals(tsmap, other.tsmap))
                return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        result = prime * result + tpn;
        result = prime * result + tslen;
        result = prime * result + Arrays.hashCode(tsmap);
        return result;
    }

    @Override
    public OduSignalID applyMask(OduSignalID mask) {
        byte[] maskTsmap = null;
        if (this.tsmap!=null && this.tsmap.length > 0) {
	       maskTsmap = new byte[this.tsmap.length];
           int i = 0;
       	   for (byte b : this.tsmap){
		       maskTsmap[i] =(byte)  (b & mask.tsmap[i++]);
           }
        }
        return new OduSignalID(this.tpn & mask.tpn,
                                   (short) (this.tslen & mask
                                           .tslen),
                                    maskTsmap);
    }

    @Override
    public int compareTo(OduSignalID o) {
        return ComparisonChain.start()
                              .compare(tpn,o.tpn)
                              .compare(tslen,o.tslen)
                              .compare(tsmap,o.tsmap, UnsignedBytes.lexicographicalComparator())
                              .result();
    }

}
