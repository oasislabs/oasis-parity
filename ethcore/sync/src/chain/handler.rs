// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use api::WARP_SYNC_PROTOCOL_ID;
use block_sync::{BlockDownloaderImportError as DownloaderImportError, DownloadAction};
use bytes::Bytes;
use ethcore::client::{BlockId, BlockImportError, BlockImportErrorKind, BlockStatus};
use ethcore::error::*;
use ethcore::header::{BlockNumber, Header as BlockHeader};
use ethcore::snapshot::{ManifestData, RestorationStatus};
use ethereum_types::{H256, U256};
use hash::keccak;
use network::PeerId;
use rlp::Rlp;
use snapshot::ChunkType;
use std::cmp;
use std::collections::HashSet;
use std::time::Instant;
use sync_io::SyncIo;

use super::{
	BlockSet, ChainSync, ForkConfirmation, PacketDecodeError, PeerAsking, PeerInfo, SyncRequester,
	SyncState, BLOCK_BODIES_PACKET, BLOCK_HEADERS_PACKET, ETH_PROTOCOL_VERSION_62,
	ETH_PROTOCOL_VERSION_63, MAX_NEW_BLOCK_AGE, MAX_NEW_HASHES, NEW_BLOCK_HASHES_PACKET,
	NEW_BLOCK_PACKET, PAR_PROTOCOL_VERSION_1, PAR_PROTOCOL_VERSION_3, PRIVATE_TRANSACTION_PACKET,
	RECEIPTS_PACKET, SIGNED_PRIVATE_TRANSACTION_PACKET, SNAPSHOT_DATA_PACKET,
	SNAPSHOT_MANIFEST_PACKET, STATUS_PACKET, TRANSACTIONS_PACKET,
};

/// The Chain Sync Handler: handles responses from peers
pub struct SyncHandler;

impl SyncHandler {
	/// Handle incoming packet from peer
	pub fn on_packet(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer: PeerId,
		packet_id: u8,
		data: &[u8],
	) {
		if packet_id != STATUS_PACKET && !sync.peers.contains_key(&peer) {
			debug!(target:"sync", "Unexpected packet {} from unregistered peer: {}:{}", packet_id, peer, io.peer_info(peer));
			return;
		}
		let rlp = Rlp::new(data);
		let result = match packet_id {
			STATUS_PACKET => SyncHandler::on_peer_status(sync, io, peer, &rlp),
			TRANSACTIONS_PACKET => SyncHandler::on_peer_transactions(sync, io, peer, &rlp),
			BLOCK_HEADERS_PACKET => SyncHandler::on_peer_block_headers(sync, io, peer, &rlp),
			BLOCK_BODIES_PACKET => SyncHandler::on_peer_block_bodies(sync, io, peer, &rlp),
			RECEIPTS_PACKET => SyncHandler::on_peer_block_receipts(sync, io, peer, &rlp),
			NEW_BLOCK_PACKET => SyncHandler::on_peer_new_block(sync, io, peer, &rlp),
			NEW_BLOCK_HASHES_PACKET => SyncHandler::on_peer_new_hashes(sync, io, peer, &rlp),
			SNAPSHOT_MANIFEST_PACKET => SyncHandler::on_snapshot_manifest(sync, io, peer, &rlp),
			SNAPSHOT_DATA_PACKET => SyncHandler::on_snapshot_data(sync, io, peer, &rlp),
			PRIVATE_TRANSACTION_PACKET => SyncHandler::on_private_transaction(sync, io, peer, &rlp),
			SIGNED_PRIVATE_TRANSACTION_PACKET => {
				SyncHandler::on_signed_private_transaction(sync, io, peer, &rlp)
			}
			_ => {
				debug!(target: "sync", "{}: Unknown packet {}", peer, packet_id);
				Ok(())
			}
		};
		result.unwrap_or_else(|e| {
			debug!(target:"sync", "{} -> Malformed packet {} : {}", peer, packet_id, e);
		})
	}

	/// Called when peer sends us new consensus packet
	pub fn on_consensus_packet(
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		trace!(target: "sync", "Received consensus packet from {:?}", peer_id);
		io.chain().queue_consensus_message(r.as_raw().to_vec());
		Ok(())
	}

	/// Called by peer when it is disconnecting
	pub fn on_peer_aborting(sync: &mut ChainSync, io: &mut SyncIo, peer_id: PeerId) {
		trace!(target: "sync", "== Disconnecting {}: {}", peer_id, io.peer_info(peer_id));
		sync.handshaking_peers.remove(&peer_id);
		if sync.peers.contains_key(&peer_id) {
			debug!(target: "sync", "Disconnected {}", peer_id);
			sync.clear_peer_download(peer_id);
			sync.peers.remove(&peer_id);
			sync.active_peers.remove(&peer_id);

			if sync.state == SyncState::SnapshotManifest {
				// Check if we are asking other peers for
				// the snapshot manifest as well.
				// If not, return to initial state
				let still_asking_manifest = sync
					.peers
					.iter()
					.filter(|&(id, p)| {
						sync.active_peers.contains(id) && p.asking == PeerAsking::SnapshotManifest
					})
					.next()
					.is_none();

				if still_asking_manifest {
					sync.state = ChainSync::get_init_state(sync.warp_sync, io.chain());
				}
			}
			sync.continue_sync(io);
		}
	}

	/// Called when a new peer is connected
	pub fn on_peer_connected(sync: &mut ChainSync, io: &mut SyncIo, peer: PeerId) {
		trace!(target: "sync", "== Connected {}: {}", peer, io.peer_info(peer));
		if let Err(e) = sync.send_status(io, peer) {
			debug!(target:"sync", "Error sending status request: {:?}", e);
			io.disconnect_peer(peer);
		} else {
			sync.handshaking_peers.insert(peer, Instant::now());
		}
	}

	/// Called by peer once it has new block bodies
	pub fn on_peer_new_block(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		if !sync.peers.get(&peer_id).map_or(false, |p| p.can_sync()) {
			trace!(target: "sync", "Ignoring new block from unconfirmed peer {}", peer_id);
			return Ok(());
		}
		let difficulty: U256 = r.val_at(1)?;
		if let Some(ref mut peer) = sync.peers.get_mut(&peer_id) {
			if peer.difficulty.map_or(true, |pd| difficulty > pd) {
				peer.difficulty = Some(difficulty);
			}
		}
		let block_rlp = r.at(0)?;
		let header_rlp = block_rlp.at(0)?;
		let h = keccak(&header_rlp.as_raw());
		trace!(target: "sync", "{} -> NewBlock ({})", peer_id, h);
		let header: BlockHeader = header_rlp.as_val()?;
		if header.number() > sync.highest_block.unwrap_or(0) {
			sync.highest_block = Some(header.number());
		}
		let mut unknown = false;
		{
			if let Some(ref mut peer) = sync.peers.get_mut(&peer_id) {
				peer.latest_hash = header.hash();
			}
		}
		let last_imported_number = sync.new_blocks.last_imported_block_number();
		if last_imported_number > header.number()
			&& last_imported_number - header.number() > MAX_NEW_BLOCK_AGE
		{
			trace!(target: "sync", "Ignored ancient new block {:?}", h);
			io.disable_peer(peer_id);
			return Ok(());
		}
		match io.chain().import_block(block_rlp.as_raw().to_vec()) {
			Err(BlockImportError(
				BlockImportErrorKind::Import(ImportErrorKind::AlreadyInChain),
				_,
			)) => {
				trace!(target: "sync", "New block already in chain {:?}", h);
			}
			Err(BlockImportError(
				BlockImportErrorKind::Import(ImportErrorKind::AlreadyQueued),
				_,
			)) => {
				trace!(target: "sync", "New block already queued {:?}", h);
			}
			Ok(_) => {
				// abort current download of the same block
				sync.complete_sync(io);
				sync.new_blocks
					.mark_as_known(&header.hash(), header.number());
				trace!(target: "sync", "New block queued {:?} ({})", h, header.number());
			}
			Err(BlockImportError(BlockImportErrorKind::Block(BlockError::UnknownParent(p)), _)) => {
				unknown = true;
				trace!(target: "sync", "New block with unknown parent ({:?}) {:?}", p, h);
			}
			Err(e) => {
				debug!(target: "sync", "Bad new block {:?} : {:?}", h, e);
				io.disable_peer(peer_id);
			}
		};
		if unknown {
			if sync.state != SyncState::Idle {
				trace!(target: "sync", "NewBlock ignored while seeking");
			} else {
				trace!(target: "sync", "New unknown block {:?}", h);
				//TODO: handle too many unknown blocks
				sync.sync_peer(io, peer_id, true);
			}
		}
		sync.continue_sync(io);
		Ok(())
	}

	/// Handles `NewHashes` packet. Initiates headers download for any unknown hashes.
	pub fn on_peer_new_hashes(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		if !sync.peers.get(&peer_id).map_or(false, |p| p.can_sync()) {
			trace!(target: "sync", "Ignoring new hashes from unconfirmed peer {}", peer_id);
			return Ok(());
		}
		let hashes: Vec<_> = r
			.iter()
			.take(MAX_NEW_HASHES)
			.map(|item| (item.val_at::<H256>(0), item.val_at::<BlockNumber>(1)))
			.collect();
		if let Some(ref mut peer) = sync.peers.get_mut(&peer_id) {
			// Peer has new blocks with unknown difficulty
			peer.difficulty = None;
			if let Some(&(Ok(ref h), _)) = hashes.last() {
				peer.latest_hash = h.clone();
			}
		}
		if sync.state != SyncState::Idle {
			trace!(target: "sync", "Ignoring new hashes since we're already downloading.");
			let max = r
				.iter()
				.take(MAX_NEW_HASHES)
				.map(|item| item.val_at::<BlockNumber>(1).unwrap_or(0))
				.fold(0u64, cmp::max);
			if max > sync.highest_block.unwrap_or(0) {
				sync.highest_block = Some(max);
			}
			sync.continue_sync(io);
			return Ok(());
		}
		trace!(target: "sync", "{} -> NewHashes ({} entries)", peer_id, r.item_count()?);
		let mut max_height: BlockNumber = 0;
		let mut new_hashes = Vec::new();
		let last_imported_number = sync.new_blocks.last_imported_block_number();
		for (rh, rn) in hashes {
			let hash = rh?;
			let number = rn?;
			if number > sync.highest_block.unwrap_or(0) {
				sync.highest_block = Some(number);
			}
			if sync.new_blocks.is_downloading(&hash) {
				continue;
			}
			if last_imported_number > number && last_imported_number - number > MAX_NEW_BLOCK_AGE {
				trace!(target: "sync", "Ignored ancient new block hash {:?}", hash);
				io.disable_peer(peer_id);
				continue;
			}
			match io.chain().block_status(BlockId::Hash(hash.clone())) {
				BlockStatus::InChain => {
					trace!(target: "sync", "New block hash already in chain {:?}", hash);
				}
				BlockStatus::Queued => {
					trace!(target: "sync", "New hash block already queued {:?}", hash);
				}
				BlockStatus::Unknown | BlockStatus::Pending => {
					new_hashes.push(hash.clone());
					if number > max_height {
						trace!(target: "sync", "New unknown block hash {:?}", hash);
						if let Some(ref mut peer) = sync.peers.get_mut(&peer_id) {
							peer.latest_hash = hash.clone();
						}
						max_height = number;
					}
				}
				BlockStatus::Bad => {
					debug!(target: "sync", "Bad new block hash {:?}", hash);
					io.disable_peer(peer_id);
					return Ok(());
				}
			}
		}
		if max_height != 0 {
			trace!(target: "sync", "Downloading blocks for new hashes");
			sync.new_blocks.reset_to(new_hashes);
			sync.state = SyncState::NewBlocks;
			sync.sync_peer(io, peer_id, true);
		}
		sync.continue_sync(io);
		Ok(())
	}

	/// Called by peer once it has new block bodies
	fn on_peer_block_bodies(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		sync.clear_peer_download(peer_id);
		let block_set = sync
			.peers
			.get(&peer_id)
			.and_then(|p| p.block_set)
			.unwrap_or(BlockSet::NewBlocks);
		if !sync.reset_peer_asking(peer_id, PeerAsking::BlockBodies) {
			trace!(target: "sync", "{}: Ignored unexpected bodies", peer_id);
			sync.continue_sync(io);
			return Ok(());
		}
		let item_count = r.item_count()?;
		trace!(target: "sync", "{} -> BlockBodies ({} entries), set = {:?}", peer_id, item_count, block_set);
		if item_count == 0 {
			sync.deactivate_peer(io, peer_id);
		} else if sync.state == SyncState::Waiting {
			trace!(target: "sync", "Ignored block bodies while waiting");
		} else {
			let result = {
				let downloader = match block_set {
					BlockSet::NewBlocks => &mut sync.new_blocks,
					BlockSet::OldBlocks => match sync.old_blocks {
						None => {
							trace!(target: "sync", "Ignored block headers while block download is inactive");
							sync.continue_sync(io);
							return Ok(());
						}
						Some(ref mut blocks) => blocks,
					},
				};
				downloader.import_bodies(io, r)
			};

			match result {
				Err(DownloaderImportError::Invalid) => {
					io.disable_peer(peer_id);
					sync.deactivate_peer(io, peer_id);
					sync.continue_sync(io);
					return Ok(());
				}
				Err(DownloaderImportError::Useless) => {
					sync.deactivate_peer(io, peer_id);
				}
				Ok(()) => (),
			}

			sync.collect_blocks(io, block_set);
			sync.sync_peer(io, peer_id, false);
		}
		sync.continue_sync(io);
		Ok(())
	}

	fn on_peer_fork_header(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		{
			let peer = sync
				.peers
				.get_mut(&peer_id)
				.expect("Is only called when peer is present in peers");
			peer.asking = PeerAsking::Nothing;
			let item_count = r.item_count()?;
			let (fork_number, fork_hash) = sync
				.fork_block
				.expect("ForkHeader request is sent only fork block is Some; qed")
				.clone();

			if item_count == 0 || item_count != 1 {
				trace!(target: "sync", "{}: Chain is too short to confirm the block", peer_id);
				peer.confirmation = ForkConfirmation::TooShort;
			} else {
				let header = r.at(0)?.as_raw();
				if keccak(&header) != fork_hash {
					trace!(target: "sync", "{}: Fork mismatch", peer_id);
					io.disable_peer(peer_id);
					return Ok(());
				}

				trace!(target: "sync", "{}: Confirmed peer", peer_id);
				peer.confirmation = ForkConfirmation::Confirmed;

				if !io.chain_overlay().read().contains_key(&fork_number) {
					trace!(target: "sync", "Inserting (fork) block {} header", fork_number);
					io.chain_overlay()
						.write()
						.insert(fork_number, header.to_vec());
				}
			}
		}

		sync.sync_peer(io, peer_id, false);
		return Ok(());
	}

	/// Called by peer once it has new block headers during sync
	fn on_peer_block_headers(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		let is_fork_header_request = match sync.peers.get(&peer_id) {
			Some(peer) if peer.asking == PeerAsking::ForkHeader => true,
			_ => false,
		};

		if is_fork_header_request {
			return SyncHandler::on_peer_fork_header(sync, io, peer_id, r);
		}

		sync.clear_peer_download(peer_id);
		let expected_hash = sync.peers.get(&peer_id).and_then(|p| p.asking_hash);
		let allowed = sync
			.peers
			.get(&peer_id)
			.map(|p| p.is_allowed())
			.unwrap_or(false);
		let block_set = sync
			.peers
			.get(&peer_id)
			.and_then(|p| p.block_set)
			.unwrap_or(BlockSet::NewBlocks);
		if !sync.reset_peer_asking(peer_id, PeerAsking::BlockHeaders)
			|| expected_hash.is_none()
			|| !allowed
		{
			trace!(target: "sync", "{}: Ignored unexpected headers, expected_hash = {:?}", peer_id, expected_hash);
			sync.continue_sync(io);
			return Ok(());
		}
		let item_count = r.item_count()?;
		trace!(target: "sync", "{} -> BlockHeaders ({} entries), state = {:?}, set = {:?}", peer_id, item_count, sync.state, block_set);
		if (sync.state == SyncState::Idle || sync.state == SyncState::WaitingPeers)
			&& sync.old_blocks.is_none()
		{
			trace!(target: "sync", "Ignored unexpected block headers");
			sync.continue_sync(io);
			return Ok(());
		}
		if sync.state == SyncState::Waiting {
			trace!(target: "sync", "Ignored block headers while waiting");
			sync.continue_sync(io);
			return Ok(());
		}

		let result = {
			let downloader = match block_set {
				BlockSet::NewBlocks => &mut sync.new_blocks,
				BlockSet::OldBlocks => match sync.old_blocks {
					None => {
						trace!(target: "sync", "Ignored block headers while block download is inactive");
						sync.continue_sync(io);
						return Ok(());
					}
					Some(ref mut blocks) => blocks,
				},
			};
			downloader.import_headers(io, r, expected_hash)
		};

		match result {
			Err(DownloaderImportError::Useless) => {
				sync.deactivate_peer(io, peer_id);
			}
			Err(DownloaderImportError::Invalid) => {
				io.disable_peer(peer_id);
				sync.deactivate_peer(io, peer_id);
				sync.continue_sync(io);
				return Ok(());
			}
			Ok(DownloadAction::Reset) => {
				// mark all outstanding requests as expired
				trace!("Resetting downloads for {:?}", block_set);
				for (_, ref mut p) in sync
					.peers
					.iter_mut()
					.filter(|&(_, ref p)| p.block_set == Some(block_set))
				{
					p.reset_asking();
				}
			}
			Ok(DownloadAction::None) => {}
		}

		sync.collect_blocks(io, block_set);
		// give a task to the same peer first if received valuable headers.
		sync.sync_peer(io, peer_id, false);
		// give tasks to other peers
		sync.continue_sync(io);
		Ok(())
	}

	/// Called by peer once it has new block receipts
	fn on_peer_block_receipts(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		sync.clear_peer_download(peer_id);
		let block_set = sync
			.peers
			.get(&peer_id)
			.and_then(|p| p.block_set)
			.unwrap_or(BlockSet::NewBlocks);
		if !sync.reset_peer_asking(peer_id, PeerAsking::BlockReceipts) {
			trace!(target: "sync", "{}: Ignored unexpected receipts", peer_id);
			sync.continue_sync(io);
			return Ok(());
		}
		let item_count = r.item_count()?;
		trace!(target: "sync", "{} -> BlockReceipts ({} entries)", peer_id, item_count);
		if item_count == 0 {
			sync.deactivate_peer(io, peer_id);
		} else if sync.state == SyncState::Waiting {
			trace!(target: "sync", "Ignored block receipts while waiting");
		} else {
			let result = {
				let downloader = match block_set {
					BlockSet::NewBlocks => &mut sync.new_blocks,
					BlockSet::OldBlocks => match sync.old_blocks {
						None => {
							trace!(target: "sync", "Ignored block headers while block download is inactive");
							sync.continue_sync(io);
							return Ok(());
						}
						Some(ref mut blocks) => blocks,
					},
				};
				downloader.import_receipts(io, r)
			};

			match result {
				Err(DownloaderImportError::Invalid) => {
					io.disable_peer(peer_id);
					sync.deactivate_peer(io, peer_id);
					sync.continue_sync(io);
					return Ok(());
				}
				Err(DownloaderImportError::Useless) => {
					sync.deactivate_peer(io, peer_id);
				}
				Ok(()) => (),
			}

			sync.collect_blocks(io, block_set);
			sync.sync_peer(io, peer_id, false);
		}
		sync.continue_sync(io);
		Ok(())
	}

	/// Called when snapshot manifest is downloaded from a peer.
	fn on_snapshot_manifest(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		if !sync.peers.get(&peer_id).map_or(false, |p| p.can_sync()) {
			trace!(target: "sync", "Ignoring snapshot manifest from unconfirmed peer {}", peer_id);
			return Ok(());
		}
		sync.clear_peer_download(peer_id);
		if !sync.reset_peer_asking(peer_id, PeerAsking::SnapshotManifest)
			|| sync.state != SyncState::SnapshotManifest
		{
			trace!(target: "sync", "{}: Ignored unexpected/expired manifest", peer_id);
			sync.continue_sync(io);
			return Ok(());
		}

		let manifest_rlp = r.at(0)?;
		let manifest = match ManifestData::from_rlp(manifest_rlp.as_raw()) {
			Err(e) => {
				trace!(target: "sync", "{}: Ignored bad manifest: {:?}", peer_id, e);
				io.disable_peer(peer_id);
				sync.continue_sync(io);
				return Ok(());
			}
			Ok(manifest) => manifest,
		};

		let is_supported_version = io
			.snapshot_service()
			.supported_versions()
			.map_or(false, |(l, h)| {
				manifest.version >= l && manifest.version <= h
			});

		if !is_supported_version {
			trace!(target: "sync", "{}: Snapshot manifest version not supported: {}", peer_id, manifest.version);
			io.disable_peer(peer_id);
			sync.continue_sync(io);
			return Ok(());
		}
		sync.snapshot
			.reset_to(&manifest, &keccak(manifest_rlp.as_raw()));
		io.snapshot_service().begin_restore(manifest);
		sync.state = SyncState::SnapshotData;

		// give a task to the same peer first.
		sync.sync_peer(io, peer_id, false);
		// give tasks to other peers
		sync.continue_sync(io);
		Ok(())
	}

	/// Called when snapshot data is downloaded from a peer.
	fn on_snapshot_data(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		if !sync.peers.get(&peer_id).map_or(false, |p| p.can_sync()) {
			trace!(target: "sync", "Ignoring snapshot data from unconfirmed peer {}", peer_id);
			return Ok(());
		}
		sync.clear_peer_download(peer_id);
		if !sync.reset_peer_asking(peer_id, PeerAsking::SnapshotData)
			|| (sync.state != SyncState::SnapshotData && sync.state != SyncState::SnapshotWaiting)
		{
			trace!(target: "sync", "{}: Ignored unexpected snapshot data", peer_id);
			sync.continue_sync(io);
			return Ok(());
		}

		// check service status
		let status = io.snapshot_service().status();
		match status {
			RestorationStatus::Inactive | RestorationStatus::Failed => {
				trace!(target: "sync", "{}: Snapshot restoration aborted", peer_id);
				sync.state = SyncState::WaitingPeers;

				// only note bad if restoration failed.
				if let (Some(hash), RestorationStatus::Failed) =
					(sync.snapshot.snapshot_hash(), status)
				{
					trace!(target: "sync", "Noting snapshot hash {} as bad", hash);
					sync.snapshot.note_bad(hash);
				}

				sync.snapshot.clear();
				sync.continue_sync(io);
				return Ok(());
			}
			RestorationStatus::Initializing { .. } => {
				trace!(target: "warp", "{}: Snapshot restoration is initializing", peer_id);
				return Ok(());
			}
			RestorationStatus::Ongoing { .. } => {
				trace!(target: "sync", "{}: Snapshot restoration is ongoing", peer_id);
			}
		}

		let snapshot_data: Bytes = r.val_at(0)?;
		match sync.snapshot.validate_chunk(&snapshot_data) {
			Ok(ChunkType::Block(hash)) => {
				trace!(target: "sync", "{}: Processing block chunk", peer_id);
				io.snapshot_service()
					.restore_block_chunk(hash, snapshot_data);
			}
			Ok(ChunkType::State(hash)) => {
				trace!(target: "sync", "{}: Processing state chunk", peer_id);
				io.snapshot_service()
					.restore_state_chunk(hash, snapshot_data);
			}
			Err(()) => {
				trace!(target: "sync", "{}: Got bad snapshot chunk", peer_id);
				io.disconnect_peer(peer_id);
				sync.continue_sync(io);
				return Ok(());
			}
		}

		if sync.snapshot.is_complete() {
			// wait for snapshot restoration process to complete
			sync.state = SyncState::SnapshotWaiting;
		}
		// give a task to the same peer first.
		sync.sync_peer(io, peer_id, false);
		// give tasks to other peers
		sync.continue_sync(io);
		Ok(())
	}

	/// Called by peer to report status
	fn on_peer_status(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		sync.handshaking_peers.remove(&peer_id);
		let protocol_version: u8 = r.val_at(0)?;
		let warp_protocol = io.protocol_version(&WARP_SYNC_PROTOCOL_ID, peer_id) != 0;
		let peer = PeerInfo {
			protocol_version: protocol_version,
			network_id: r.val_at(1)?,
			difficulty: Some(r.val_at(2)?),
			latest_hash: r.val_at(3)?,
			genesis: r.val_at(4)?,
			asking: PeerAsking::Nothing,
			asking_blocks: Vec::new(),
			asking_hash: None,
			ask_time: Instant::now(),
			last_sent_transactions: HashSet::new(),
			expired: false,
			confirmation: if sync.fork_block.is_none() {
				ForkConfirmation::Confirmed
			} else {
				ForkConfirmation::Unconfirmed
			},
			asking_snapshot_data: None,
			snapshot_hash: if warp_protocol {
				Some(r.val_at(5)?)
			} else {
				None
			},
			snapshot_number: if warp_protocol {
				Some(r.val_at(6)?)
			} else {
				None
			},
			block_set: None,
		};

		trace!(target: "sync", "New peer {} (protocol: {}, network: {:?}, difficulty: {:?}, latest:{}, genesis:{}, snapshot:{:?})",
			peer_id, peer.protocol_version, peer.network_id, peer.difficulty, peer.latest_hash, peer.genesis, peer.snapshot_number);
		if io.is_expired() {
			trace!(target: "sync", "Status packet from expired session {}:{}", peer_id, io.peer_info(peer_id));
			return Ok(());
		}

		if sync.peers.contains_key(&peer_id) {
			debug!(target: "sync", "Unexpected status packet from {}:{}", peer_id, io.peer_info(peer_id));
			return Ok(());
		}
		let chain_info = io.chain().chain_info();
		if peer.genesis != chain_info.genesis_hash {
			io.disable_peer(peer_id);
			trace!(target: "sync", "Peer {} genesis hash mismatch (ours: {}, theirs: {})", peer_id, chain_info.genesis_hash, peer.genesis);
			return Ok(());
		}
		if peer.network_id != sync.network_id {
			io.disable_peer(peer_id);
			trace!(target: "sync", "Peer {} network id mismatch (ours: {}, theirs: {})", peer_id, sync.network_id, peer.network_id);
			return Ok(());
		}

		if false
			|| (warp_protocol
				&& (peer.protocol_version < PAR_PROTOCOL_VERSION_1.0
					|| peer.protocol_version > PAR_PROTOCOL_VERSION_3.0))
			|| (!warp_protocol
				&& (peer.protocol_version < ETH_PROTOCOL_VERSION_62.0
					|| peer.protocol_version > ETH_PROTOCOL_VERSION_63.0))
		{
			io.disable_peer(peer_id);
			trace!(target: "sync", "Peer {} unsupported eth protocol ({})", peer_id, peer.protocol_version);
			return Ok(());
		}

		if sync.sync_start_time.is_none() {
			sync.sync_start_time = Some(Instant::now());
		}

		sync.peers.insert(peer_id.clone(), peer);
		// Don't activate peer immediatelly when searching for common block.
		// Let the current sync round complete first.
		sync.active_peers.insert(peer_id.clone());
		debug!(target: "sync", "Connected {}:{}", peer_id, io.peer_info(peer_id));

		match sync.fork_block {
			Some((fork_block, _)) => {
				SyncRequester::request_fork_header(sync, io, peer_id, fork_block);
			}
			_ => {
				// when there's no `fork_block` defined we initialize the peer with
				// `confirmation: ForkConfirmation::Confirmed`.
				sync.sync_peer(io, peer_id, false);
			}
		}

		Ok(())
	}

	/// Called when peer sends us new transactions
	fn on_peer_transactions(
		sync: &mut ChainSync,
		io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		// Accept transactions only when fully synced
		if !io.is_chain_queue_empty()
			|| (sync.state != SyncState::Idle && sync.state != SyncState::NewBlocks)
		{
			trace!(target: "sync", "{} Ignoring transactions while syncing", peer_id);
			return Ok(());
		}
		if !sync.peers.get(&peer_id).map_or(false, |p| p.can_sync()) {
			trace!(target: "sync", "{} Ignoring transactions from unconfirmed/unknown peer", peer_id);
			return Ok(());
		}

		let item_count = r.item_count()?;
		trace!(target: "sync", "{:02} -> Transactions ({} entries)", peer_id, item_count);
		let mut transactions = Vec::with_capacity(item_count);
		for i in 0..item_count {
			let rlp = r.at(i)?;
			let tx = rlp.as_raw().to_vec();
			transactions.push(tx);
		}
		io.chain().queue_transactions(transactions, peer_id);
		Ok(())
	}

	/// Called when peer sends us signed private transaction packet
	fn on_signed_private_transaction(
		sync: &ChainSync,
		_io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		if !sync.peers.get(&peer_id).map_or(false, |p| p.can_sync()) {
			trace!(target: "sync", "{} Ignoring packet from unconfirmed/unknown peer", peer_id);
			return Ok(());
		}

		trace!(target: "sync", "Received signed private transaction packet from {:?}", peer_id);
		if let Err(e) = sync
			.private_tx_handler
			.import_signed_private_transaction(r.as_raw())
		{
			trace!(target: "sync", "Ignoring the message, error queueing: {}", e);
		}
		Ok(())
	}

	/// Called when peer sends us new private transaction packet
	fn on_private_transaction(
		sync: &ChainSync,
		_io: &mut SyncIo,
		peer_id: PeerId,
		r: &Rlp,
	) -> Result<(), PacketDecodeError> {
		if !sync.peers.get(&peer_id).map_or(false, |p| p.can_sync()) {
			trace!(target: "sync", "{} Ignoring packet from unconfirmed/unknown peer", peer_id);
			return Ok(());
		}

		trace!(target: "sync", "Received private transaction packet from {:?}", peer_id);

		if let Err(e) = sync
			.private_tx_handler
			.import_private_transaction(r.as_raw())
		{
			trace!(target: "sync", "Ignoring the message, error queueing: {}", e);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use ethcore::client::{ChainInfo, EachBlockWith, TestBlockChainClient};
	use parking_lot::RwLock;
	use rlp::Rlp;
	use std::collections::VecDeque;
	use tests::helpers::TestIo;
	use tests::snapshot::TestSnapshotService;

	use super::super::tests::{
		dummy_sync_with_peer, get_dummy_block, get_dummy_blocks, get_dummy_hashes,
	};
	use super::*;

	#[test]
	fn handles_peer_new_hashes() {
		let mut client = TestBlockChainClient::new();
		client.add_blocks(10, EachBlockWith::Uncle);
		let queue = RwLock::new(VecDeque::new());
		let mut sync = dummy_sync_with_peer(client.block_hash_delta_minus(5), &client);
		let ss = TestSnapshotService::new();
		let mut io = TestIo::new(&mut client, &ss, &queue, None);

		let hashes_data = get_dummy_hashes();
		let hashes_rlp = Rlp::new(&hashes_data);

		let result = SyncHandler::on_peer_new_hashes(&mut sync, &mut io, 0, &hashes_rlp);

		assert!(result.is_ok());
	}

	#[test]
	fn handles_peer_new_block_malformed() {
		let mut client = TestBlockChainClient::new();
		client.add_blocks(10, EachBlockWith::Uncle);

		let block_data = get_dummy_block(11, client.chain_info().best_block_hash);

		let queue = RwLock::new(VecDeque::new());
		let mut sync = dummy_sync_with_peer(client.block_hash_delta_minus(5), &client);
		//sync.have_common_block = true;
		let ss = TestSnapshotService::new();
		let mut io = TestIo::new(&mut client, &ss, &queue, None);

		let block = Rlp::new(&block_data);

		let result = SyncHandler::on_peer_new_block(&mut sync, &mut io, 0, &block);

		assert!(result.is_err());
	}

	#[test]
	fn handles_peer_new_block() {
		let mut client = TestBlockChainClient::new();
		client.add_blocks(10, EachBlockWith::Uncle);

		let block_data = get_dummy_blocks(11, client.chain_info().best_block_hash);

		let queue = RwLock::new(VecDeque::new());
		let mut sync = dummy_sync_with_peer(client.block_hash_delta_minus(5), &client);
		let ss = TestSnapshotService::new();
		let mut io = TestIo::new(&mut client, &ss, &queue, None);

		let block = Rlp::new(&block_data);

		let result = SyncHandler::on_peer_new_block(&mut sync, &mut io, 0, &block);

		assert!(result.is_ok());
	}

	#[test]
	fn handles_peer_new_block_empty() {
		let mut client = TestBlockChainClient::new();
		client.add_blocks(10, EachBlockWith::Uncle);
		let queue = RwLock::new(VecDeque::new());
		let mut sync = dummy_sync_with_peer(client.block_hash_delta_minus(5), &client);
		let ss = TestSnapshotService::new();
		let mut io = TestIo::new(&mut client, &ss, &queue, None);

		let empty_data = vec![];
		let block = Rlp::new(&empty_data);

		let result = SyncHandler::on_peer_new_block(&mut sync, &mut io, 0, &block);

		assert!(result.is_err());
	}

	#[test]
	fn handles_peer_new_hashes_empty() {
		let mut client = TestBlockChainClient::new();
		client.add_blocks(10, EachBlockWith::Uncle);
		let queue = RwLock::new(VecDeque::new());
		let mut sync = dummy_sync_with_peer(client.block_hash_delta_minus(5), &client);
		let ss = TestSnapshotService::new();
		let mut io = TestIo::new(&mut client, &ss, &queue, None);

		let empty_hashes_data = vec![];
		let hashes_rlp = Rlp::new(&empty_hashes_data);

		let result = SyncHandler::on_peer_new_hashes(&mut sync, &mut io, 0, &hashes_rlp);

		assert!(result.is_ok());
	}
}
