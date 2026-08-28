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
#include "HeaderConsistencyChecker.h"

#include "Json/Json.h"
#include "Storage.h"
#include "Util.h"

#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

HeaderConsistencyChecker::HeaderConsistencyChecker(Storage &storage_, BitcoinD_RPCInfo rpcInfo_, QObject *parent)
    : QObject(parent), storage(storage_), rpcInfo(std::move(rpcInfo_))
{}

HeaderConsistencyChecker::~HeaderConsistencyChecker() {}

void HeaderConsistencyChecker::start(DoneCallback cb)
{
    doneCb = std::move(cb);
    nextHeight = 0;
    endHeightExclusive = storage.latestHeight() ? *storage.latestHeight() + 1u : 0u;
    if (!endHeightExclusive) {
        finish({true, -1, {}});
        return;
    }
    Log() << "Verifying " << endHeightExclusive << " " << Util::Pluralize("header", endHeightExclusive)
          << " against yentend (batched) ...";
    checkNextChunk();
}

void HeaderConsistencyChecker::finish(Result res)
{
    if (isDone) return; // defensive; should not happen
    isDone = true;
    if (doneCb) doneCb(std::move(res));
}

void HeaderConsistencyChecker::postBatch(const QVariantList &requests, const std::function<void(QNetworkReply *)> &onFinished)
{
    QUrl url;
    url.setScheme(rpcInfo.tls ? "https" : "http");
    url.setHost(rpcInfo.hostPort.first);
    url.setPort(rpcInfo.hostPort.second);
    url.setPath("/");

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "text/plain");
    const auto [user, pass] = rpcInfo.getUserPass();
    if (!user.isEmpty() || !pass.isEmpty()) {
        const QByteArray authVal = "Basic " + QByteArray((user + ":" + pass).toUtf8()).toBase64();
        req.setRawHeader("Authorization", authVal);
    }
    // Force a fresh connection for every request rather than letting Qt reuse a pooled keep-alive one. yentend
    // (like bitcoind) may silently close idle connections on its own timeout; if Qt reuses one just as the peer
    // has dropped it, the write stalls until a TCP-level retransmission timeout expires before Qt notices and
    // retries -- this shows up as sporadic multi-second stalls on an otherwise-fast batched call. A fresh TCP
    // handshake on a local/nearby daemon costs low single-digit milliseconds, far cheaper than that stall.
    req.setRawHeader("Connection", "close");
    req.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, false);
    req.setTransferTimeout(30'000); // 30 sec per batch; generous since a batch may be sizeable

    const QByteArray body = Json::toUtf8(requests, true);
    QNetworkReply *reply = nam.post(req, body);
    connect(reply, &QNetworkReply::finished, this, [reply, onFinished] {
        onFinished(reply);
        reply->deleteLater();
    });
}

/* static */
bool HeaderConsistencyChecker::parseBatchResponse(const QByteArray &body, QHash<unsigned, QVariant> &outResultsById, QString *err)
{
    QVariant parsed;
    try {
        parsed = Json::parseUtf8(body);
    } catch (const std::exception &e) {
        if (err) *err = QString("Failed to parse JSON-RPC batch response: %1").arg(e.what());
        return false;
    }
    if (parsed.type() != QVariant::List) {
        if (err) *err = "JSON-RPC batch response was not a JSON array as expected";
        return false;
    }
    for (const auto &itemV : parsed.toList()) {
        if (itemV.type() != QVariant::Map) {
            if (err) *err = "JSON-RPC batch response item was not an object";
            return false;
        }
        const auto item = itemV.toMap();
        bool idOk = false;
        const unsigned id = item.value("id").toUInt(&idOk);
        if (!idOk) {
            if (err) *err = "JSON-RPC batch response item missing a usable numeric \"id\"";
            return false;
        }
        if (const auto errVal = item.value("error"); errVal.isValid() && !errVal.isNull()) {
            if (err) *err = QString("yentend returned an error for height %1: %2").arg(id).arg(Json::toUtf8(errVal, true).constData());
            return false;
        }
        outResultsById[id] = item.value("result");
    }
    return true;
}

void HeaderConsistencyChecker::checkNextChunk()
{
    const BlockHeight chunkStart = nextHeight;
    const BlockHeight chunkEnd = std::min(chunkStart + kChunkSize, endHeightExclusive); // exclusive

    QVariantList hashRequests;
    hashRequests.reserve(int(chunkEnd - chunkStart));
    for (BlockHeight h = chunkStart; h < chunkEnd; ++h)
        hashRequests.push_back(QVariantMap{{"jsonrpc", "1.0"}, {"id", h}, {"method", "getblockhash"}, {"params", QVariantList{h}}});

    postBatch(hashRequests, [this, chunkStart, chunkEnd](QNetworkReply *reply) {
        if (isDone) return;
        if (reply->error() != QNetworkReply::NoError) {
            finish({false, -1, QString("Network error fetching block hashes from yentend: %1").arg(reply->errorString())});
            return;
        }
        QHash<unsigned, QVariant> hashesById;
        QString err;
        if (!parseBatchResponse(reply->readAll(), hashesById, &err)) {
            finish({false, -1, QString("Error fetching block hashes from yentend: %1").arg(err)});
            return;
        }

        QVariantList headerRequests;
        headerRequests.reserve(int(chunkEnd - chunkStart));
        for (BlockHeight h = chunkStart; h < chunkEnd; ++h) {
            const auto it = hashesById.constFind(h);
            if (it == hashesById.constEnd()) {
                finish({false, -1, QString("yentend did not return a hash for height %1").arg(h)});
                return;
            }
            headerRequests.push_back(QVariantMap{{"jsonrpc", "1.0"}, {"id", h}, {"method", "getblockheader"},
                                                  {"params", QVariantList{it.value(), false}}});
        }

        postBatch(headerRequests, [this, chunkStart, chunkEnd](QNetworkReply *reply2) {
            if (isDone) return;
            if (reply2->error() != QNetworkReply::NoError) {
                finish({false, -1, QString("Network error fetching headers from yentend: %1").arg(reply2->errorString())});
                return;
            }
            QHash<unsigned, QVariant> rawHdrsById;
            QString err2;
            if (!parseBatchResponse(reply2->readAll(), rawHdrsById, &err2)) {
                finish({false, -1, QString("Error fetching headers from yentend: %1").arg(err2)});
                return;
            }

            QString serr;
            const auto ourHeaders = storage.headersFromHeight(chunkStart, chunkEnd - chunkStart, &serr);
            if (ourHeaders.size() != size_t(chunkEnd - chunkStart)) {
                finish({false, -1, QString("Could not read our own stored headers for heights [%1, %2): %3")
                                        .arg(chunkStart).arg(chunkEnd).arg(serr)});
                return;
            }

            for (BlockHeight h = chunkStart; h < chunkEnd; ++h) {
                const auto it = rawHdrsById.constFind(h);
                if (it == rawHdrsById.constEnd()) {
                    finish({false, -1, QString("yentend did not return a header for height %1").arg(h)});
                    return;
                }
                const QByteArray daemonRaw = Util::ParseHexFast(it.value().toByteArray());
                const QByteArray &ourRaw = ourHeaders[size_t(h - chunkStart)];
                if (daemonRaw.isEmpty() || daemonRaw != ourRaw) {
                    finish({true, int(h), {}}); // first mismatch -- report it, caller decides what to do
                    return;
                }
            }

            Log() << "Verifying headers against yentend: " << chunkEnd << "/" << endHeightExclusive
                  << " (" << QString::number(double(chunkEnd) / double(endHeightExclusive) * 100.0, 'f', 1) << "%) ...";

            nextHeight = chunkEnd;
            if (nextHeight >= endHeightExclusive)
                finish({true, -1, {}});
            else
                checkNextChunk();
        });
    });
}
