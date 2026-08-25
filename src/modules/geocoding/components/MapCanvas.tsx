import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type PointerEvent as ReactPointerEvent,
  type KeyboardEvent as ReactKeyboardEvent,
} from 'react';
import { Minus, Plus } from 'lucide-react';
import { cn } from '@/shared/utils/cn';
import {
  MAP_ATTRIBUTION,
  MAP_ATTRIBUTION_URL,
  MAP_TILE_URL,
  MAX_ZOOM,
  MIN_ZOOM,
} from '../constants/mapConstants';
import {
  TILE_SIZE,
  clamp,
  project,
  roundCoord,
  unproject,
  type WorldPoint,
} from '../utils/mercator';
import type { LatLng } from '../types/geocodingTypes';

/** Movement, in px, under which a pointer down/up counts as a tap, not a drag. */
const TAP_SLOP_PX = 5;
/** Wheel delta adding up to one zoom level — one notch of a mouse, several of a trackpad. */
const WHEEL_ZOOM_THRESHOLD = 80;
/** Pixels an arrow key pans. */
const KEY_PAN_PX = 80;
/** Pinch scale change that triggers a zoom step. */
const PINCH_IN = 1.55;
const PINCH_OUT = 1 / PINCH_IN;
/** Quiet time after a pan/zoom before the parent is told where the map ended up. */
const VIEW_SETTLE_MS = 300;

export interface MapView {
  center: LatLng;
  zoom: number;
}

interface MapCanvasProps {
  /** Opening view, and where the map jumps to when this changes. */
  view: MapView;
  /** The picked point, or null. Drawn as the pin. */
  marker: LatLng | null;
  /** A tap, click or Enter — always a deliberate choice of point. */
  onPick: (point: LatLng) => void;
  /** Reported once a pan/zoom settles, so search can bias to what is on screen. */
  onViewChange?: (view: MapView) => void;
  className?: string;
}

const tileUrl = (z: number, x: number, y: number): string =>
  MAP_TILE_URL.replace('{z}', String(z))
    .replace('{x}', String(x))
    .replace('{y}', String(y));

/**
 * A raster (XYZ) tile map with pan, zoom and one marker — enough to choose a
 * point, and nothing else.
 *
 * Built on `utils/mercator` rather than on Leaflet/MapLibre: the app carries NO
 * map dependency today, ships a hand-built UI kit rather than a component
 * library (see shared/ui), and the whole requirement here is pan + zoom + a pin.
 * See the note in mercator.ts for where a real map library slots in if the
 * product ever needs routes, clusters or polygons — everything outside this file
 * speaks only lat/lng.
 *
 * The view is held HERE, not by the parent. Panning changes it dozens of times a
 * second, and routing that through the modal's state would re-render the search
 * list, the address label and the footer on every frame of a drag. The parent
 * pushes a new `view` when it wants the map to move (a search hit, a GPS fix)
 * and hears back, once the gesture settles, through `onViewChange`.
 */
export function MapCanvas({
  view,
  marker,
  onPick,
  onViewChange,
  className,
}: MapCanvasProps) {
  const container = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [current, setCurrent] = useState<MapView>(view);

  // The parent asked for a different view (a search hit, "use my location").
  // Keyed by VALUE, not object identity: an unrelated parent re-render must not
  // yank a map the user has just panned back to where it started.
  const requested = `${view.center.lat},${view.center.lng},${view.zoom}`;
  useEffect(() => {
    setCurrent(view);
    // `view` is deliberately not a dependency — `requested` is its value.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requested]);

  // Report where the map ended up, not every frame of getting there: the only
  // consumer biases searches to the visible area, which does not need 60Hz.
  const onViewChangeRef = useRef(onViewChange);
  onViewChangeRef.current = onViewChange;
  useEffect(() => {
    const id = window.setTimeout(
      () => onViewChangeRef.current?.(current),
      VIEW_SETTLE_MS,
    );
    return () => window.clearTimeout(id);
  }, [current]);

  useEffect(() => {
    const element = container.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => {
      const box = entry.contentRect;
      setSize({ width: box.width, height: box.height });
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  /** World-pixel coordinate of the container's top-left corner. */
  const origin = useMemo(
    (): WorldPoint => {
      const centerPx = project(current.center, current.zoom);
      return {
        x: centerPx.x - size.width / 2,
        y: centerPx.y - size.height / 2,
      };
    },
    [current, size.width, size.height],
  );

  const toLatLng = useCallback(
    (offsetX: number, offsetY: number): LatLng => {
      const point = unproject(
        { x: origin.x + offsetX, y: origin.y + offsetY },
        current.zoom,
      );
      return { lat: roundCoord(point.lat), lng: roundCoord(point.lng) };
    },
    [origin, current.zoom],
  );

  /**
   * Zoom while keeping whatever is under (offsetX, offsetY) exactly there — the
   * behaviour every map has, and the reason a wheel zoom feels aimed at
   * something rather than at the middle of the box.
   */
  const zoomAround = useCallback(
    (offsetX: number, offsetY: number, delta: number) => {
      setCurrent((previous) => {
        const zoom = clamp(previous.zoom + delta, MIN_ZOOM, MAX_ZOOM);
        if (zoom === previous.zoom) return previous;
        const centerPx = project(previous.center, previous.zoom);
        const anchor = unproject(
          {
            x: centerPx.x - size.width / 2 + offsetX,
            y: centerPx.y - size.height / 2 + offsetY,
          },
          previous.zoom,
        );
        const anchorAtNewZoom = project(anchor, zoom);
        return {
          zoom,
          center: unproject(
            {
              x: anchorAtNewZoom.x + (size.width / 2 - offsetX),
              y: anchorAtNewZoom.y + (size.height / 2 - offsetY),
            },
            zoom,
          ),
        };
      });
    },
    [size.width, size.height],
  );

  const panBy = useCallback((dx: number, dy: number) => {
    setCurrent((previous) => {
      const centerPx = project(previous.center, previous.zoom);
      return {
        zoom: previous.zoom,
        center: unproject(
          { x: centerPx.x - dx, y: centerPx.y - dy },
          previous.zoom,
        ),
      };
    });
  }, []);

  // Live pointers, so one finger pans and two pinch. Refs rather than state:
  // these change on every move event and nothing renders from them.
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const gesture = useRef({ moved: 0, pinchDistance: 0 });

  const pinchDistance = (): number => {
    const [a, b] = [...pointers.current.values()];
    if (!a || !b) return 0;
    return Math.hypot(a.x - b.x, a.y - b.y);
  };

  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    (event.currentTarget as Element).setPointerCapture?.(event.pointerId);
    pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY });
    if (pointers.current.size === 1) gesture.current.moved = 0;
    if (pointers.current.size === 2) gesture.current.pinchDistance = pinchDistance();
  };

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const previous = pointers.current.get(event.pointerId);
    if (!previous) return;
    const dx = event.clientX - previous.x;
    const dy = event.clientY - previous.y;
    pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY });
    gesture.current.moved += Math.abs(dx) + Math.abs(dy);

    if (pointers.current.size === 1) {
      panBy(dx, dy);
      return;
    }
    if (pointers.current.size === 2 && gesture.current.pinchDistance > 0) {
      const distance = pinchDistance();
      const ratio = distance / gesture.current.pinchDistance;
      if (ratio > PINCH_IN || ratio < PINCH_OUT) {
        const box = container.current?.getBoundingClientRect();
        const [a, b] = [...pointers.current.values()];
        zoomAround(
          box && a && b ? (a.x + b.x) / 2 - box.left : size.width / 2,
          box && a && b ? (a.y + b.y) / 2 - box.top : size.height / 2,
          ratio > 1 ? 1 : -1,
        );
        gesture.current.pinchDistance = distance;
      }
    }
  };

  const endPointer = (event: ReactPointerEvent<HTMLDivElement>) => {
    const wasSingle = pointers.current.size === 1;
    pointers.current.delete(event.pointerId);
    if (pointers.current.size < 2) gesture.current.pinchDistance = 0;
    // A tap places the pin; a drag must not. Without the slop test every pan
    // that happens to end over a building drops a marker nobody asked for.
    if (
      event.type === 'pointerup' &&
      wasSingle &&
      gesture.current.moved <= TAP_SLOP_PX
    ) {
      const box = container.current?.getBoundingClientRect();
      if (box) onPick(toLatLng(event.clientX - box.left, event.clientY - box.top));
    }
  };

  // Wheel is bound NATIVELY, not through onWheel: React registers its wheel
  // listener passively, so preventDefault() there is ignored and zooming the map
  // would scroll the modal behind it at the same time.
  useEffect(() => {
    const element = container.current;
    if (!element) return;
    let accumulated = 0;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      accumulated += event.deltaY;
      if (Math.abs(accumulated) < WHEEL_ZOOM_THRESHOLD) return;
      const box = element.getBoundingClientRect();
      zoomAround(
        event.clientX - box.left,
        event.clientY - box.top,
        accumulated < 0 ? 1 : -1,
      );
      accumulated = 0;
    };
    element.addEventListener('wheel', onWheel, { passive: false });
    return () => element.removeEventListener('wheel', onWheel);
  }, [zoomAround]);

  // A keyboard equivalent for every gesture above. A map that can only be driven
  // by dragging is a map a keyboard user cannot set a location with at all.
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const pickCenter = () => onPick(toLatLng(size.width / 2, size.height / 2));
    const zoomCenter = (delta: number) =>
      zoomAround(size.width / 2, size.height / 2, delta);
    const keys: Record<string, () => void> = {
      ArrowUp: () => panBy(0, KEY_PAN_PX),
      ArrowDown: () => panBy(0, -KEY_PAN_PX),
      ArrowLeft: () => panBy(KEY_PAN_PX, 0),
      ArrowRight: () => panBy(-KEY_PAN_PX, 0),
      '+': () => zoomCenter(1),
      '=': () => zoomCenter(1),
      '-': () => zoomCenter(-1),
      Enter: pickCenter,
      ' ': pickCenter,
    };
    const handler = keys[event.key];
    if (!handler) return;
    event.preventDefault();
    handler();
  };

  const tiles = useMemo(() => {
    if (size.width === 0 || size.height === 0) return [];
    const count = 2 ** current.zoom;
    const firstX = Math.floor(origin.x / TILE_SIZE);
    const lastX = Math.floor((origin.x + size.width) / TILE_SIZE);
    const firstY = Math.floor(origin.y / TILE_SIZE);
    const lastY = Math.floor((origin.y + size.height) / TILE_SIZE);
    const grid: Array<{ key: string; url: string; left: number; top: number }> = [];
    for (let x = firstX; x <= lastX; x += 1) {
      for (let y = firstY; y <= lastY; y += 1) {
        // Above the north pole and below the south there is no tile — the world
        // is finite vertically. Horizontally it wraps, so x is taken modulo the
        // row, which is what makes dragging past the date line keep drawing map.
        if (y < 0 || y >= count) continue;
        const wrappedX = ((x % count) + count) % count;
        grid.push({
          key: `${current.zoom}/${x}/${y}`,
          url: tileUrl(current.zoom, wrappedX, y),
          left: x * TILE_SIZE - origin.x,
          top: y * TILE_SIZE - origin.y,
        });
      }
    }
    return grid;
  }, [current.zoom, origin, size.width, size.height]);

  const markerPosition = useMemo(() => {
    if (!marker) return null;
    const point = project(marker, current.zoom);
    return { left: point.x - origin.x, top: point.y - origin.y };
  }, [marker, current.zoom, origin]);

  return (
    <div
      ref={container}
      role="application"
      aria-label="Map. Drag to pan, scroll to zoom, click or press Enter to choose a point."
      tabIndex={0}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endPointer}
      onPointerCancel={endPointer}
      onKeyDown={onKeyDown}
      className={cn(
        'relative overflow-hidden rounded-lg border border-border/[0.12] bg-surface-raised',
        // `touch-none` hands every touch gesture to the handlers above; without
        // it the browser scrolls the modal instead of panning the map.
        'cursor-grab touch-none select-none active:cursor-grabbing',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50',
        className,
      )}
    >
      {tiles.map((tile) => (
        <img
          key={tile.key}
          src={tile.url}
          alt=""
          draggable={false}
          className="pointer-events-none absolute h-[256px] w-[256px] max-w-none"
          style={{ left: tile.left, top: tile.top }}
        />
      ))}

      {markerPosition && (
        <span
          aria-hidden
          className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full"
          style={{ left: markerPosition.left, top: markerPosition.top }}
        >
          {/* Drawn rather than borrowed from the icon set: a pin has to point AT
              its coordinate, so the tip is the anchor and the shape has to end
              in one. */}
          <svg width="26" height="34" viewBox="0 0 26 34" className="drop-shadow-lg">
            <path
              d="M13 33C13 33 24 20.5 24 13A11 11 0 1 0 2 13c0 7.5 11 20 11 20Z"
              className="fill-primary stroke-primary-foreground"
              strokeWidth="1.5"
            />
            <circle cx="13" cy="13" r="4.2" className="fill-primary-foreground" />
          </svg>
        </span>
      )}

      <div className="absolute right-2.5 top-2.5 z-10 flex flex-col gap-1">
        <ZoomButton
          label="Zoom in"
          onClick={() => zoomAround(size.width / 2, size.height / 2, 1)}
        >
          <Plus className="h-4 w-4" />
        </ZoomButton>
        <ZoomButton
          label="Zoom out"
          onClick={() => zoomAround(size.width / 2, size.height / 2, -1)}
        >
          <Minus className="h-4 w-4" />
        </ZoomButton>
      </div>

      {/* Attribution is not decoration: OSM's licence — and every commercial
          provider's terms — require the credit to be visible on the map. */}
      <a
        href={MAP_ATTRIBUTION_URL}
        target="_blank"
        rel="noreferrer"
        onPointerDown={(event) => event.stopPropagation()}
        className="absolute bottom-0 right-0 z-10 rounded-tl-[8px] bg-bg/80 px-1.5 py-0.5 text-[10px] text-muted hover:text-foreground"
      >
        {MAP_ATTRIBUTION}
      </a>
    </div>
  );
}

function ZoomButton({
  label,
  onClick,
  children,
}: {
  label: string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      // The map's gestures are handled on the parent; without stopping the
      // pointer here a click on + would also register as a tap on the map and
      // move the pin to wherever the button happens to sit.
      onPointerDown={(event) => event.stopPropagation()}
      onPointerUp={(event) => event.stopPropagation()}
      onClick={onClick}
      className="flex h-7 w-7 items-center justify-center rounded-sm border border-border/[0.12] bg-bg/85 text-foreground shadow-sm hover:bg-bg"
    >
      {children}
    </button>
  );
}
