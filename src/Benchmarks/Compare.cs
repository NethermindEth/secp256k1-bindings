// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using BenchmarkDotNet.Attributes;
using Nethermind.Crypto.Secp256k1.Test;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Benchmarks;
public class Compare
{
    [Benchmark]
    public void RunTestsNew()
    {
        var tests = new SecP256k1Tests();

        tests.Does_not_allow_empty_key();
        //tests.Does_allow_valid_keys();
        //tests.Can_get_compressed_public_key();
        //tests.Can_get_uncompressed_public_key();
        //tests.Can_sign();
        //tests.Can_recover_compressed();
        //tests.Can_calculate_agreement();
        //tests.Can_calculate_agreement("103aaccf80ad53c11ce2d1654e733a70835b852bfa4528a6214f11a9b9c6e55c", "44007cacdca37c4fbdf1c22ea314e03a3e5b7d76e88fe02743af6c1f4786237d9b5a1e8e2781dde9d5caa3db193ab3c0364b6d5883216aa040b3c2e00a3f618f", "d0ab6bbdc1e1bc5c189d843a0ed4ae18bb76b1afbe4c2b6ffed66992402f8f90");
        //tests.Can_calculate_agreement("e9088ce6d8df1357233e1cde9ad58a910a26605bd1921570977d6708b96e37b5", "e41845daecae897d10025873e9ff98008819027d1503d8b04cdbdb987583852da0171ec64c04ab7234ee4a268124cade10bbb8db8c4dd49ca7da371ea4e3074b", "542c718db53e6b8af98f8903e2f6afa39da3b892d9bc9f152f87f8f3d9c046fb");
        //tests.Can_calculate_agreement_serialized("103aaccf80ad53c11ce2d1654e733a70835b852bfa4528a6214f11a9b9c6e55c", "7d2386471f6caf4327e08fe8767d5b3e3ae014a32ec2f1bd4f7ca3dcac7c00448f613f0ae0c2b340a06a2183586d4b36c0b33a19dba3cad5e9dd81278e1e5a9b", "d0ab6bbdc1e1bc5c189d843a0ed4ae18bb76b1afbe4c2b6ffed66992402f8f90");
        //tests.Can_recover_uncompressed();
    }

    [Benchmark]
    public void RunTestsOld()
    {
        var tests = new Nethermind.Crypto2.Secp256k1.Test.SecP256k1Tests();

        tests.Does_not_allow_empty_key();
        //tests.Does_allow_valid_keys();
        //tests.Can_get_compressed_public_key();
        //tests.Can_get_uncompressed_public_key();
        //tests.Can_sign();
        //tests.Can_recover_compressed();
        //tests.Can_calculate_agreement();
        //tests.Can_calculate_agreement("103aaccf80ad53c11ce2d1654e733a70835b852bfa4528a6214f11a9b9c6e55c", "44007cacdca37c4fbdf1c22ea314e03a3e5b7d76e88fe02743af6c1f4786237d9b5a1e8e2781dde9d5caa3db193ab3c0364b6d5883216aa040b3c2e00a3f618f", "d0ab6bbdc1e1bc5c189d843a0ed4ae18bb76b1afbe4c2b6ffed66992402f8f90");
        //tests.Can_calculate_agreement("e9088ce6d8df1357233e1cde9ad58a910a26605bd1921570977d6708b96e37b5", "e41845daecae897d10025873e9ff98008819027d1503d8b04cdbdb987583852da0171ec64c04ab7234ee4a268124cade10bbb8db8c4dd49ca7da371ea4e3074b", "542c718db53e6b8af98f8903e2f6afa39da3b892d9bc9f152f87f8f3d9c046fb");
        //tests.Can_calculate_agreement_serialized("103aaccf80ad53c11ce2d1654e733a70835b852bfa4528a6214f11a9b9c6e55c", "7d2386471f6caf4327e08fe8767d5b3e3ae014a32ec2f1bd4f7ca3dcac7c00448f613f0ae0c2b340a06a2183586d4b36c0b33a19dba3cad5e9dd81278e1e5a9b", "d0ab6bbdc1e1bc5c189d843a0ed4ae18bb76b1afbe4c2b6ffed66992402f8f90");
        //tests.Can_recover_uncompressed();
    }
}
