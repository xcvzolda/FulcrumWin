//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#pragma once

#include "BitcoinD_RPCInfo.h"
#include "BlockProcTypes.h"

#include <QByteArray>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <QVariantList>

#include <functional>

class Storage;
class QNetworkReply;

/// One-shot helper: verifies Storage's on-disk headers against the live bitcoind daemon using batched JSON-RPC
/// (getblockhash + getblockheader) instead of recomputing header hashes locally.
///
/// Why this exists: for some coins (e.g. YTN) the local header hash is a deliberately memory-hard/slow PoW
/// function (Yespower, pre-fork), which makes a from-genesis local re-verification of a multi-million-header
/// chain take well over an hour, single-threaded, before any listener opens. bitcoind already trusts its own
/// on-disk block index without re-deriving PoW hashes on load (see e.g. yenten-core's
/// CBlockTreeDB::LoadBlockIndexGuts), so asking it for the hash/header at each height is dramatically cheaper
/// than recomputing it ourselves, and it has the added benefit of catching reorgs against the daemon's *current*
/// view, not just our own historical self-consistency.
///
/// Deliberately implemented as a fully self-contained QNetworkAccessManager-based HTTP client, entirely separate
/// from BitcoinDMgr/BitcoinD -- it does not touch or share any state with the shared, always-in-use daemon
/// connection machinery used by the rest of the app, so it cannot affect it even if something here misbehaves.
class HeaderConsistencyChecker : public QObject
{
    Q_OBJECT
public:
    HeaderConsistencyChecker(Storage &storage, BitcoinD_RPCInfo rpcInfo, QObject *parent = nullptr);
    ~HeaderConsistencyChecker() override;

    struct Result {
        bool ok = false; ///< false if the check could not be completed at all (network/RPC failure) -- caller should
                          ///< treat this as "unable to verify", not as "verification failed"
        int mismatchHeight = -1; ///< only meaningful if ok == true. -1 if the whole checked range matched;
                                  ///< otherwise the height of the first header that didn't match bitcoind's version
        QString errorString; ///< set if ok == false
    };
    using DoneCallback = std::function<void(Result)>;

    /// Kicks off the async check for heights [0, storage.latestHeight()+1) as captured at the moment this is
    /// called. May only be called once per instance. `cb` is guaranteed to be called exactly once, asynchronously.
    void start(DoneCallback cb);

    /// How many heights we verify per pair of batched RPC calls (getblockhash, then getblockheader). Chosen based
    /// on real-world benchmarking against a local bitcoind: throughput levels off well before this size while
    /// keeping each individual HTTP request/response comfortably small.
    static constexpr unsigned kChunkSize = 10'000;

private:
    void checkNextChunk();
    void postBatch(const QVariantList &requests, const std::function<void(QNetworkReply *)> &onFinished);
    /// Parses an HTTP JSON-RPC batch response body into a map of id (as originally sent, i.e. height) -> result.
    /// On any structural problem (non-array response, missing ids, any item carrying an "error") returns false.
    static bool parseBatchResponse(const QByteArray &body, QHash<unsigned, QVariant> &outResultsById, QString *err);
    void finish(Result);

    Storage &storage;
    const BitcoinD_RPCInfo rpcInfo;
    QNetworkAccessManager nam;
    DoneCallback doneCb;
    BlockHeight nextHeight = 0, endHeightExclusive = 0;
    bool isDone = false;
};
